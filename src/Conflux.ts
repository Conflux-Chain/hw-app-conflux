import { foreach } from "./utils";
import type Transport from "@ledgerhq/hw-transport";
import { sign } from "js-conflux-sdk/dist/js-conflux-sdk.umd.min.js";
import BIPPath from "bip32-path";

const remapTransactionRelatedErrors = (e) => {
  if (e && e.statusCode === 0x6a80) {
    throw new Error(
      "Missing a parameter. Try enabling blind signature in the app"
    );
  }

  return e;
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

  constructor(
    transport: Transport,
    scrambleKey = "conflux_default_scramble_key"
  ) {
    this.transport = transport;
    transport.decorateAppAPIMethods(
      this,
      ["getAddress", "signTransaction"],
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
    const pathBuffer = this.pathToBuffer(path);
    return this.transport
      .send(
        0xe0,
        0x02,
        boolDisplay ? 0x01 : 0x00,
        boolChaincode ? 0x01 : 0x00,
        pathBuffer
      )
      .then((response) => {
        const publicKeyLength = response[0];
        const publicKey = response
          .slice(1, 1 + publicKeyLength)
          .toString("hex");

        return {
          publicKey,
          address:
            "0x" +
            sign
              .publicKeyToAddress(Buffer.from(publicKey, "hex"))
              .toString("hex"),
          chainCode: boolChaincode
            ? response
                .slice(1 + publicKeyLength + 1, 1 + publicKeyLength + 1 + 32)
                .toString("hex")
            : undefined,
        };
      });
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
        .send(0xe0, 0x03, i === 0 ? 0x00 : 0x80, 0x00, data)
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

  async getAppConfiguration(): Promise<{
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
