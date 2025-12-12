import { foreach, isLegacyVersion, splitMessage, splitPath } from "./utils";
import type Transport from "@ledgerhq/hw-transport";
import { sign, format } from "js-conflux-sdk";
import BIPPath from "bip32-path";

import type {
  EIP712FieldDefinition,
  EIP712ImplementationEntry,
} from "./eip712/types";
import { EIP712_P1, EIP712_P2, sendEIP712Payload } from "./eip712/transport";
import { encodeFieldDefinition, normalizeFieldValue } from "./eip712/codec";
import { prepareEIP712Payload, type EIP712TypedData } from "./eip712/typedData";

const remapTransactionRelatedErrors = (e) => {
  if (e && e.statusCode === 0x6a80) {
    throw new Error(
      "Missing a parameter. Try enabling blind signature in the app"
    );
  }

  return e;
};
const CLA = 0xe0;
const P1 = {
  first: 0x00,
};
const P2 = {
  more: 0x80,
  last: 0x00,
};

const INS = {
  GET_ADDRESS: 0x02,
  SIGN_TX: 0x03,
  SIGN_PERSONAL_MESSAGE: 0x04,
  SIGN_EIP712: 0x0a,
  EIP712_SEND_STRUCT_DEFINITION: 0x0b,
  EIP712_SEND_STRUCT_IMPLEMENTATION: 0x0c,
};

const CHAINID = {
  MAINNET: 1029,
  TESTNET: 1,
};

/**
 * Conflux API
 *
 * @param transport a transport for sending commands to a device
 * @param scrambleKey a scramble key
 *
 * @example
 * import Cfx from "@ledgerhq/hw-app-conflux";
 * const cfx = new Cfx(transport)
 */

export default class Conflux {
  transport: Transport;
  chainId: number;
  constructor(
    transport: Transport,
    chainId: number,
    scrambleKey = "conflux_default_scramble_key"
  ) {
    this.transport = transport;
    this.chainId = chainId || CHAINID.MAINNET;
    transport.decorateAppAPIMethods(
      this,
      [
        "getAddress",
        "signTransaction",
        "getAppConfiguration",
        "signPersonalMessage",
        "signEIP712Message",
      ],
      scrambleKey
    );
  }

  /**
   * get Conflux address for a given BIP 32 path.
   * @param path a path in BIP 32 format
   * @option boolDisplay optionally enable or not the display
   * @option boolChaincode optionally enable or not the chaincode request
   * @return an object with a publicKey, address and (optionally) chainCode
   * @example
   * cfx.getAddress("44'/503'/0'/0/0").then(o => o.publicKey)
   * cfx.getAddress("44'/503'/0'/0/0",true).then(o => o.publicKey): show mainnet address
   */
  getAddress(
    path: string,
    boolDisplay?: boolean,
    boolChaincode?: boolean
  ): Promise<{
    publicKey: string;
    address: string;
    chainCode?: string;
  }> {
    //path buffer
    let buffer = this.derivationPathToBuffer(path);

    //chainID buffer
    if (boolDisplay) {
      const chainIdBuffer = Buffer.alloc(4);
      chainIdBuffer.writeUInt32BE(this.chainId);
      buffer = Buffer.concat([buffer, chainIdBuffer]);
    }

    return this.transport
      .send(
        0xe0,
        INS.GET_ADDRESS,
        boolDisplay ? 0x01 : 0x00,
        boolChaincode ? 0x01 : 0x00,
        buffer
      )
      .then((response) => {
        const publicKeyLength = response[0];
        const publicKey = response
          .slice(2, 1 + publicKeyLength)
          .toString("hex"); // remove the prefix:04, because 04 means the uncompressed public key

        const address = format.address(
          `0x${sign["publicKeyToAddress"](
            Buffer.from(publicKey, "hex")
          ).toString("hex")}`,
          this.chainId
        ); //CIP-37 address
        let chainCode;
        if (boolChaincode) {
          const chainCodeLength = response[1 + publicKeyLength];
          chainCode = response
            .slice(
              1 + publicKeyLength + 1,
              1 + publicKeyLength + 1 + chainCodeLength
            )
            .toString("hex");
        }
        return {
          publicKey,
          address,
          chainCode,
        };
      });
  }

  private async _legacy_signTransaction(
    path: string,
    rawTxHex: string
  ): Promise<{
    s: string;
    v: string;
    r: string;
  }> {
    const paths = BIPPath.fromString(path).toPathArray();
    let offset = 0;

    const rawTx = Buffer.from(rawTxHex, "hex");

    const toSend: Buffer[] = [];
    let response;
    while (offset !== rawTx.length) {
      const maxChunkSize = offset === 0 ? 150 - 1 - paths.length * 4 : 150;
      const chunkSize =
        offset + maxChunkSize > rawTx.length
          ? rawTx.length - offset
          : maxChunkSize;

      const buffer = Buffer.alloc(
        offset === 0 ? 1 + paths.length * 4 + chunkSize : chunkSize
      );

      if (offset === 0) {
        buffer[0] = paths.length;
        paths.forEach((element, index) => {
          buffer.writeUInt32BE(element, 1 + 4 * index);
        });
        rawTx.copy(buffer, 1 + 4 * paths.length, offset, offset + chunkSize);
      } else {
        rawTx.copy(buffer, 0, offset, offset + chunkSize);
      }

      toSend.push(buffer);
      offset += chunkSize;
    }

    return foreach(toSend, (data, i) =>
      this.transport
        .send(0xe0, INS.SIGN_TX, i === 0 ? 0x00 : 0x80, 0x00, data)
        .then((apduResponse) => {
          response = apduResponse;
        })
    ).then(
      () => {
        const response_byte: number = response.slice(0, 1)[0];
        const v = response_byte.toString(16);
        const r = response.slice(1, 1 + 32).toString("hex");
        const s = response.slice(1 + 32, 1 + 32 + 32).toString("hex");
        return {
          v,
          r,
          s,
        };
      },
      (e) => {
        throw remapTransactionRelatedErrors(e);
      }
    );
  }

  private async _signTransaction(
    path: string,
    rawTxHex: string
  ): Promise<{
    s: string;
    v: string;
    r: string;
  }> {
    const rawTx = Buffer.from(rawTxHex, "hex");
    const derivationPathBuff = this.derivationPathToBuffer(path);
    // send bip32
    await this.transport.send(
      CLA,
      INS.SIGN_TX,
      P1.first,
      P2.more,
      derivationPathBuff
    );

    const payloadChunks = splitMessage(rawTx, 255);
    // send data chunks
    if (payloadChunks.length > 1) {
      for (let i = 0; i < payloadChunks.length - 1; i++) {
        const chunk = payloadChunks[i];
        await this.transport.send(CLA, INS.SIGN_TX, i + 1, P2.more, chunk);
      }
    }

    const response = await this.transport.send(
      CLA,
      INS.SIGN_TX,
      Math.max(payloadChunks.length - 1, 1),
      P2.last,
      payloadChunks[payloadChunks.length - 1]
    );

    const response_byte: number = response.subarray(0, 1)[0];
    const v = response_byte.toString(16);
    const r = response.subarray(1, 1 + 32).toString("hex");
    const s = response.subarray(1 + 32, 1 + 32 + 32).toString("hex");
    return {
      v,
      r,
      s,
    };
  }

  /**
   * You can sign a transaction and retrieve v, r, s given the raw transaction and the BIP 32 path of the account to sign
   * @example
   cfx.signTransaction("44'/503'/0'/0/0", "e8018504e3b292008252089428ee52a8f3d6e5d15f8b131996950d7f296c7952872bd72a2487400080").then(result => ...)
   */
  async signTransaction(
    path: string,
    rawTxHex: string
  ): Promise<{
    s: string;
    v: string;
    r: string;
  }> {
    const { version } = await this._getAppConfiguration();

    const isLegacy = isLegacyVersion(version);

    if (isLegacy) return this._legacy_signTransaction(path, rawTxHex);

    return this._signTransaction(path, rawTxHex);
  }

  private async _getAppConfiguration(): Promise<{
    name: string;
    version: string;
    flags: number | Buffer;
  }> {
    const r = await this.transport.send(0xb0, 0x01, 0x00, 0x00);
    let i = 0;
    const format = r[i++];

    if (format !== 1) {
      throw new Error("getAppAndVersion: format not supported");
    }

    const nameLength = r[i++];
    const name = r.slice(i, (i += nameLength)).toString("ascii");
    const versionLength = r[i++];
    const version = r.slice(i, (i += versionLength)).toString("ascii");
    const flagLength = r[i++];
    const flags = r.slice(i, (i += flagLength));
    return {
      name,
      version,
      flags,
    };
  }
  async getAppConfiguration(): Promise<{
    name: string;
    version: string;
    flags: number | Buffer;
  }> {
    return this._getAppConfiguration();
  }

  /**
   * You can sign a message according to cfx_sign RPC call and retrieve v, r, s given the message and the BIP 32 path of the account to sign.
   * @example cfx.signPersonalMessage("44'/503'/0'/0/0", Buffer.from("test").toString("hex"))
   * @param path hdPath
   * @param messageHex the hex string of the message
   * @returns
   */
  signPersonalMessage(
    path: string,
    messageHex: string
  ): Promise<{
    v: number;
    s: string;
    r: string;
  }> {
    const message = Buffer.from(messageHex, "hex");
    const pathBuffer = this.derivationPathToBuffer(path);
    const messageChunks = splitMessage(message, 255);

    // Firmware allows at most 0x20 personal-sign message chunks
    // https://github.com/Conflux-Chain/app-conflux/blob/develop/docs/APDU.md#request-format-3
    if (messageChunks.length > 0x20) {
      throw new Error(
        "Message too long: firmware allows at most 0x20 personal-sign chunks"
      );
    }

    const chunks = [pathBuffer, ...messageChunks];
    let response;

    return foreach(chunks, (data, index) => {
      const p1 = index === 0 ? 0x00 : index;
      const p2 = index === chunks.length - 1 ? 0x00 : 0x80;
      return this.transport
        .send(0xe0, INS.SIGN_PERSONAL_MESSAGE, p1, p2, data)
        .then((apduResponse) => {
          response = apduResponse;
        });
    }).then(() => {
      const v = response[0];
      const r = response.slice(1, 1 + 32).toString("hex");
      const s = response.slice(1 + 32, 1 + 32 + 32).toString("hex");
      return {
        v,
        r,
        s,
      };
    });
  }

  private pathToBuffer(originalPath: string) {
    const path = originalPath
      .split("/")
      .map((value) =>
        value.endsWith("'") || value.endsWith("h") ? value : value + "'"
      )
      .join("/");
    const pathNums: number[] = BIPPath.fromString(path).toPathArray();
    return this.serializePath(pathNums);
  }

  private serializePath(path: number[]) {
    const buf = Buffer.alloc(1 + path.length * 4);
    buf.writeUInt8(path.length, 0);
    for (const [i, num] of path.entries()) {
      buf.writeUInt32BE(num, 1 + i * 4);
    }
    return buf;
  }

  /**
   * Encodes derivation path using legacy splitPath rules.
   * This avoids auto-hardening and matches existing APIs.
   */
  private derivationPathToBuffer(path: string): Buffer {
    const paths = splitPath(path);
    const buf = Buffer.alloc(1 + paths.length * 4);
    buf[0] = paths.length;
    paths.forEach((element, index) => {
      buf.writeUInt32BE(element, 1 + 4 * index);
    });
    return buf;
  }

  private async _sendEIP712StructDefinition(
    structName: string,
    fields: EIP712FieldDefinition[]
  ): Promise<void> {
    if (!structName) throw new Error("Struct name is required");

    const nameBuf = Buffer.from(structName, "utf8");
    if (nameBuf.length === 0 || nameBuf.length > 0xff) {
      throw new Error("Struct name must be between 1 and 255 bytes");
    }

    // Definition APDU must be sent as a single complete chunk.
    await this.transport.send(
      CLA,
      INS.EIP712_SEND_STRUCT_DEFINITION,
      EIP712_P1.complete,
      EIP712_P2.structName,
      nameBuf
    );

    for (const field of fields) {
      const payload = encodeFieldDefinition(field);
      if (payload.length > 0xff) {
        throw new Error(`Field definition for ${field.name} exceeds 255 bytes`);
      }

      await this.transport.send(
        CLA,
        INS.EIP712_SEND_STRUCT_DEFINITION,
        EIP712_P1.complete,
        EIP712_P2.structField,
        payload
      );
    }
  }

  private async _sendEIP712StructImplementation(
    entries: EIP712ImplementationEntry[]
  ): Promise<void> {
    if (!entries.length) {
      throw new Error("At least one implementation entry is required");
    }

    let rootDefined = false;

    for (const entry of entries) {
      if (entry.type === "root") {
        rootDefined = true;

        const rootNameBuf = Buffer.from(entry.name, "utf8");
        if (rootNameBuf.length === 0 || rootNameBuf.length > 0xff) {
          throw new Error("Root struct name must be between 1 and 255 bytes");
        }

        await this.transport.send(
          CLA,
          INS.EIP712_SEND_STRUCT_IMPLEMENTATION,
          EIP712_P1.complete,
          EIP712_P2.structName,
          rootNameBuf
        );
        continue;
      }

      if (!rootDefined) {
        throw new Error(
          "Root struct must be set before sending arrays or fields"
        );
      }

      if (entry.type === "array") {
        if (entry.size < 0 || entry.size > 0xff) {
          throw new Error("Array size must be in [0, 255]");
        }
        await sendEIP712Payload(
          this.transport,
          CLA,
          INS.EIP712_SEND_STRUCT_IMPLEMENTATION,
          EIP712_P2.array,
          Buffer.from([entry.size])
        );
        continue;
      }

      const value = normalizeFieldValue(entry.value);
      if (value.length > 0xffff) {
        throw new Error("Field value exceeds maximum length (65535 bytes)");
      }

      const prefix = Buffer.alloc(2);
      prefix.writeUInt16BE(value.length);
      await sendEIP712Payload(
        this.transport,
        CLA,
        INS.EIP712_SEND_STRUCT_IMPLEMENTATION,
        EIP712_P2.structField,
        Buffer.concat([prefix, value])
      );
    }
  }
  private async finalizeEIP712Signature(path: string): Promise<{
    v: number;
    r: string;
    s: string;
  }> {
    const pathBuffer = this.derivationPathToBuffer(path);
    const response = await this.transport.send(
      CLA,
      INS.SIGN_EIP712,
      EIP712_P1.complete,
      EIP712_P2.signFullImplementation,
      pathBuffer
    );

    const v = response[0];
    const r = response.subarray(1, 33).toString("hex");
    const s = response.subarray(33, 65).toString("hex");
    return { v, r, s };
  }

  async signEIP712Message(
    path: string,
    typedData: EIP712TypedData
  ): Promise<{
    v: number;
    r: string;
    s: string;
  }> {
    if (typedData) {
      const { definitions, implementation } = prepareEIP712Payload(typedData);
      for (const def of definitions) {
        await this._sendEIP712StructDefinition(def.name, def.fields);
      }
      await this._sendEIP712StructImplementation(implementation);
    }

    return this.finalizeEIP712Signature(path);
  }
}
