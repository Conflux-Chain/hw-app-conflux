export type EIP712FieldKind =
  | "custom"
  | "int"
  | "uint"
  | "address"
  | "bool"
  | "string"
  | "fixed-bytes"
  | "dynamic-bytes";

export type EIP712ArrayLevel =
  | { kind: "dynamic" }
  | { kind: "fixed"; length: number };

export type EIP712FieldType =
  | { kind: "custom"; structName: string }
  | { kind: "int" | "uint"; size: number }
  | { kind: "address" | "bool" | "string" }
  | { kind: "fixed-bytes"; size: number }
  | { kind: "dynamic-bytes" };

export type EIP712FieldDefinition = {
  name: string;
  type: EIP712FieldType;
  arrayLevels?: EIP712ArrayLevel[];
};

export type EIP712ImplementationEntry =
  | { type: "root"; name: string }
  | { type: "array"; size: number }
  | { type: "field"; value: Buffer | Uint8Array };
