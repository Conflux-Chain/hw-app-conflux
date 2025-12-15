import type Transport from "@ledgerhq/hw-transport";
import { splitMessage } from "../utils";

export const EIP712_P1 = {
  complete: 0x00,
  partial: 0x01,
} as const;

export const EIP712_P2 = {
  structName: 0x00,
  structField: 0xff,
  array: 0x0f,
  signFullImplementation: 0x01,
} as const;

/**
 * Sends EIP712 payload to device, chunking if necessary.
 * Splits payloads larger than 255 bytes into multiple APDUs.
 */
export async function sendEIP712Payload(
  transport: Transport,
  cla: number,
  ins: number,
  p2: number,
  payload: Buffer
): Promise<void> {
  if (payload.length === 0) {
    await transport.send(cla, ins, EIP712_P1.complete, p2, payload);
    return;
  }

  const chunks = splitMessage(payload, 0xff);
  for (let i = 0; i < chunks.length; i++) {
    const isLast = i === chunks.length - 1;
    const p1 = isLast ? EIP712_P1.complete : EIP712_P1.partial;
    await transport.send(cla, ins, p1, p2, chunks[i]);
  }
}
