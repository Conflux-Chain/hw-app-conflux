import {
  foreach,
  isLegacyVersion,
  splitMessage,
  splitPath,
} from "./utils";
import type Transport from "@ledgerhq/hw-transport";
import { sign, format } from "js-conflux-sdk";
import BIPPath from "bip32-path";

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
      ],
      scrambleKey
    );
  }

  /**
   * get Conflux address for a given BIP 32 path.
   * @param path a path in BIP 32 format
   * @option boolAddress optionally enable or not the display the address
   * @option boolChaincode optionally enable or not the chaincode request
   * @return an object with a publicKey, address and (optionally) chainCode
   * @example
   * cfx.getAddress("44'/503'/0'/0/0").then(o => o.publicKey)
   * cfx.getAddress("44'/503'/0'/0/0",true).then(o => o.publicKey): show mainnet address
   */
  getAddress(
    path: string,
    boolAddress?: boolean,
    boolChaincode?: boolean
  ): Promise<{
    publicKey: string;
    address: string;
    chainCode?: string;
  }> {
    //path buffer
    const paths = splitPath(path);
    let buffer = Buffer.alloc(1 + paths.length * 4);
    buffer[0] = paths.length;
    paths.forEach((element, index) => {
      buffer.writeUInt32BE(element, 1 + 4 * index);
    });

    //chainID buffer
    if (boolAddress) {
      const chainIdBuffer = Buffer.alloc(4);
      chainIdBuffer.writeUInt32BE(this.chainId);
      buffer = Buffer.concat([buffer, chainIdBuffer]);
    }

    return this.transport
      .send(
        0xe0,
        INS.GET_ADDRESS,
        boolAddress ? 0x01 : 0x00,
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

  async _legacy_signTransaction(
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

  async _1559_signTransaction(
    path: string,
    rawTxHex: string
  ): Promise<{
    s: string;
    v: string;
    r: string;
  }> {
    const rawTx = Buffer.from(rawTxHex, "hex");
    const paths = splitPath(path);
    const derivationPathBuff = Buffer.alloc(1 + paths.length * 4);
    derivationPathBuff[0] = paths.length;
    paths.forEach((element, index) => {
      derivationPathBuff.writeUInt32BE(element, 1 + 4 * index);
    });
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

    return this._1559_signTransaction(path, rawTxHex);
  }

  async _getAppConfiguration(): Promise<{
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
    const paths = splitPath(path);
    let offset = 0;
    const message = Buffer.from(messageHex, "hex");
    const toSend: Buffer[] = [];
    let response;

    while (offset !== message.length) {
      const maxChunkSize =
        offset === 0 ? 150 - 1 - paths.length * 4 - 4 - 4 : 150;
      const chunkSize =
        offset + maxChunkSize > message.length
          ? message.length - offset
          : maxChunkSize;
      const buffer = Buffer.alloc(
        offset === 0 ? 1 + paths.length * 4 + 4 + 4 + chunkSize : chunkSize
      );

      if (offset === 0) {
        buffer[0] = paths.length;
        paths.forEach((element, index) => {
          buffer.writeUInt32BE(element, 1 + 4 * index);
        });
        buffer.writeUInt32BE(this.chainId, 1 + paths.length * 4);
        buffer.writeUInt32BE(message.length, 1 + 4 * paths.length + 4);
        message.copy(
          buffer,
          1 + 4 * paths.length + 4 + 4,
          offset,
          offset + chunkSize
        );
      } else {
        message.copy(buffer, 0, offset, offset + chunkSize);
      }

      toSend.push(buffer);
      offset += chunkSize;
    }

    return foreach(toSend, (data, i) =>
      this.transport
        .send(
          0xe0,
          INS.SIGN_PERSONAL_MESSAGE,
          i === 0 ? 0x00 : 0x80,
          0x00,
          data
        )
        .then((apduResponse) => {
          response = apduResponse;
        })
    ).then(() => {
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
}
