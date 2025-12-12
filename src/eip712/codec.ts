import type {
  EIP712ArrayLevel,
  EIP712FieldDefinition,
  EIP712FieldKind,
  EIP712FieldType,
} from "./types";

const EIP712_TYPE_VALUE: Record<EIP712FieldKind, number> = {
  custom: 0,
  int: 1,
  uint: 2,
  address: 3,
  bool: 4,
  string: 5,
  "fixed-bytes": 6,
  "dynamic-bytes": 7,
};

/**
 * Encodes an EIP712 field definition into binary format for the device.
 *
 * Format: typeDesc [typeName] [typeSize] [arrayLevels] keyName
 * - typeDesc: 1 byte (bit7: hasArray, bit6: hasSize, bits0-3: typeValue)
 * - typeName: length + utf8 (custom types only)
 * - typeSize: 1 byte (sized types only)
 * - arrayLevels: encoded array levels (arrays only)
 * - keyName: length + utf8
 */
export function encodeFieldDefinition(field: EIP712FieldDefinition): Buffer {
  if (!field.name) throw new Error("Field name is required");
  const arrayLevels = field.arrayLevels ?? [];
  const { typeValue, typeName, typeSize } = resolveFieldType(field.type);
  let typeDesc = typeValue & 0x0f;
  if (arrayLevels.length > 0) typeDesc |= 0x80;
  if (typeof typeSize === "number") typeDesc |= 0x40;

  const parts: Buffer[] = [Buffer.from([typeDesc])];

  if (typeName) {
    const typeNameBuf = Buffer.from(typeName, "utf8");
    if (typeNameBuf.length > 0xff)
      throw new Error("Custom type name cannot exceed 255 bytes");
    parts.push(Buffer.from([typeNameBuf.length]), typeNameBuf);
  }

  if (typeof typeSize === "number") {
    parts.push(Buffer.from([typeSize]));
  }

  if (arrayLevels.length > 0) {
    parts.push(encodeArrayLevels(arrayLevels));
  }

  const keyNameBuf = Buffer.from(field.name, "utf8");
  if (keyNameBuf.length === 0 || keyNameBuf.length > 0xff) {
    throw new Error("Field key name must be between 1 and 255 bytes");
  }
  parts.push(Buffer.from([keyNameBuf.length]), keyNameBuf);

  return Buffer.concat(parts);
}

function encodeArrayLevels(arrayLevels: EIP712ArrayLevel[]): Buffer {
  if (arrayLevels.length > 0xff) {
    throw new Error("Array level count cannot exceed 255");
  }

  const parts: Buffer[] = [Buffer.from([arrayLevels.length])];

  for (const level of arrayLevels) {
    if (level.kind === "dynamic") {
      parts.push(Buffer.from([0]));
    } else {
      if (
        !Number.isInteger(level.length) ||
        level.length <= 0 ||
        level.length > 0xff
      ) {
        throw new Error("Fixed array length must be between 1 and 255");
      }
      parts.push(Buffer.from([1, level.length]));
    }
  }

  return Buffer.concat(parts);
}
function resolveFieldType(type: EIP712FieldType): {
  typeValue: number;
  typeName?: string;
  typeSize?: number;
} {
  switch (type.kind) {
    case "custom":
      if (!type.structName)
        throw new Error("Custom field must specify a struct name");
      return {
        typeValue: EIP712_TYPE_VALUE.custom,
        typeName: type.structName,
      };
    case "int":
    case "uint":
      if (!Number.isInteger(type.size) || type.size <= 0 || type.size > 32) {
        throw new Error("Integer sizes must be between 1 and 32 bytes");
      }
      return {
        typeValue: EIP712_TYPE_VALUE[type.kind],
        typeSize: type.size,
      };
    case "fixed-bytes":
      if (!Number.isInteger(type.size) || type.size <= 0 || type.size > 32) {
        throw new Error("Fixed bytes size must be between 1 and 32");
      }
      return {
        typeValue: EIP712_TYPE_VALUE["fixed-bytes"],
        typeSize: type.size,
      };
    case "dynamic-bytes":
      return { typeValue: EIP712_TYPE_VALUE["dynamic-bytes"] };
    case "address":
    case "bool":
    case "string":
      return { typeValue: EIP712_TYPE_VALUE[type.kind] };
    default:
      throw new Error(`Unsupported field type: ${(type as any).kind}`);
  }
}

export function normalizeFieldValue(value: Buffer | Uint8Array): Buffer {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value);
  throw new Error("Field values must be Buffer or Uint8Array instances");
}
