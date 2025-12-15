import type {
  EIP712ArrayLevel,
  EIP712FieldDefinition,
  EIP712FieldKind,
  EIP712FieldType,
  EIP712ImplementationEntry,
} from "./types";

export type EIP712Types = Record<string, Array<{ name: string; type: string }>>;

export type EIP712TypedData = {
  types: EIP712Types;
  primaryType: string;
  domain: Record<string, unknown>;
  message: Record<string, unknown>;
};

type StructMetaField = {
  name: string;
  kind: EIP712FieldKind;
  size?: number;
  structName?: string;
  arrayLevels: Array<number | null>;
};

type StructMetaMap = Record<string, StructMetaField[]>;

export type PreparedDefinition = {
  name: string;
  fields: EIP712FieldDefinition[];
};

const EIP712_DOMAIN = "EIP712Domain";
const CIP23_DOMAIN = "CIP23Domain";

/**
 * Prepares EIP712 typed data for signing by extracting field definitions
 * and building implementation entries for transmission to the device.
 */
export function prepareEIP712Payload(typedData: EIP712TypedData): {
  definitions: PreparedDefinition[];
  implementation: EIP712ImplementationEntry[];
} {
  const { definitions, metaMap } = buildDefinitions(typedData.types);
  const implementation = buildImplementation(metaMap, typedData);
  return { definitions, implementation };
}

function buildDefinitions(types: EIP712Types): {
  definitions: PreparedDefinition[];
  metaMap: StructMetaMap;
} {
  const definitions: PreparedDefinition[] = [];
  const metaMap: StructMetaMap = {};

  const sortedEntries = Object.entries(types).sort(([a], [b]) =>
    a.localeCompare(b)
  );

  sortedEntries.forEach(([structName, fields]) => {
    const parsedFields: EIP712FieldDefinition[] = [];
    const metaFields: StructMetaField[] = [];

    fields.forEach((field) => {
      const parsed = parseTypeDescriptor(field.type);
      const definition: EIP712FieldDefinition = {
        name: field.name,
        type: parsed.fieldType,
      };
      if (parsed.arrayLevels.length > 0) {
        definition.arrayLevels = parsed.arrayLevels.map((level) =>
          level === null
            ? { kind: "dynamic" }
            : { kind: "fixed", length: level }
        );
      }

      parsedFields.push(definition);
      metaFields.push({
        name: field.name,
        kind: parsed.kind,
        size: parsed.size,
        structName: parsed.structName,
        arrayLevels: parsed.arrayLevels,
      });
    });

    definitions.push({ name: structName, fields: parsedFields });
    metaMap[structName] = metaFields;
  });

  return { definitions, metaMap };
}

function buildImplementation(
  metaMap: StructMetaMap,
  typedData: EIP712TypedData
): EIP712ImplementationEntry[] {
  const entries: EIP712ImplementationEntry[] = [];

  const hasEip712Domain = Boolean(metaMap[EIP712_DOMAIN]);
  const hasCip23Domain = Boolean(metaMap[CIP23_DOMAIN]);

  if (hasEip712Domain && hasCip23Domain) {
    throw new Error(
      "Ambiguous domain: both EIP712Domain and CIP23Domain are present"
    );
  }

  const domainRoot = hasEip712Domain
    ? EIP712_DOMAIN
    : hasCip23Domain
    ? CIP23_DOMAIN
    : null;

  if (domainRoot) {
    entries.push({ type: "root", name: domainRoot });
    entries.push(...encodeStruct(metaMap, domainRoot, typedData.domain));
  }

  const { primaryType } = typedData;
  if (!metaMap[primaryType]) {
    throw new Error(`Unknown primaryType ${primaryType}`);
  }

  entries.push({ type: "root", name: primaryType });
  entries.push(...encodeStruct(metaMap, primaryType, typedData.message));

  return entries;
}

function parseTypeDescriptor(rawType: string): {
  fieldType: EIP712FieldType;
  kind: EIP712FieldKind;
  size?: number;
  structName?: string;
  arrayLevels: Array<number | null>;
} {
  const { baseType, arrayLevels } = extractArrayLevels(rawType);
  const { typeName, typeSize } = extractTypeName(baseType);

  let fieldType: EIP712FieldType;
  let kind: EIP712FieldKind = "custom";
  let size: number | undefined;
  let structName: string | undefined;

  switch (typeName) {
    case "int":
    case "uint": {
      if (typeof typeSize !== "number" || typeSize % 8 !== 0) {
        throw new Error(`${typeName} must specify a size multiple of 8`);
      }
      const byteSize = typeSize / 8;
      if (byteSize < 1 || byteSize > 32) {
        throw new Error(`${typeName} size must be between 8 and 256 bits`);
      }
      fieldType = { kind: typeName, size: byteSize };
      kind = typeName;
      size = byteSize;
      break;
    }
    case "bytes": {
      if (typeof typeSize === "number") {
        if (typeSize < 1 || typeSize > 32) {
          throw new Error("bytesN size must be between 1 and 32");
        }
        fieldType = { kind: "fixed-bytes", size: typeSize };
        kind = "fixed-bytes";
        size = typeSize;
      } else {
        fieldType = { kind: "dynamic-bytes" };
        kind = "dynamic-bytes";
      }
      break;
    }
    case "address":
    case "bool":
    case "string": {
      fieldType = { kind: typeName };
      kind = typeName;
      break;
    }
    default: {
      fieldType = { kind: "custom", structName: typeName };
      structName = typeName;
      break;
    }
  }

  return { fieldType, kind, size, structName, arrayLevels };
}

function extractArrayLevels(type: string): {
  baseType: string;
  arrayLevels: Array<number | null>;
} {
  const arrayLevels: Array<number | null> = [];
  let remaining = type;

  const pattern = /(.*)\[([0-9]*)\]$/;
  while (true) {
    const match = remaining.match(pattern);
    if (!match) break;
    remaining = match[1];
    const level = match[2].length ? parseInt(match[2], 10) : null;
    arrayLevels.unshift(level);
  }

  return { baseType: remaining, arrayLevels };
}

function extractTypeName(type: string): {
  typeName: string;
  typeSize?: number;
} {
  const match = type.match(/^(\w+?)(\d*)$/);
  if (!match) {
    throw new Error(`Invalid type descriptor: ${type}`);
  }
  const typeName = match[1];
  const typeSize = match[2].length ? parseInt(match[2], 10) : undefined;
  return { typeName, typeSize };
}

function encodeStruct(
  metaMap: StructMetaMap,
  structName: string,
  data: Record<string, unknown>
): EIP712ImplementationEntry[] {
  const metaFields = metaMap[structName];
  if (!metaFields) {
    throw new Error(`Unknown struct ${structName}`);
  }

  const entries: EIP712ImplementationEntry[] = [];

  metaFields.forEach((field) => {
    const value = (data as Record<string, unknown>)[field.name];
    if (typeof value === "undefined") {
      throw new Error(`Missing value for field ${field.name} in ${structName}`);
    }
    entries.push(...encodeField(metaMap, field, value));
  });

  return entries;
}

function encodeField(
  metaMap: StructMetaMap,
  field: StructMetaField,
  value: unknown
): EIP712ImplementationEntry[] {
  if (field.arrayLevels.length > 0) {
    if (!Array.isArray(value)) {
      throw new Error(`Field ${field.name} expects an array`);
    }
    const [currentLevel, ...rest] = field.arrayLevels;
    if (currentLevel !== null && value.length !== currentLevel) {
      throw new Error(
        `Array ${field.name} expects length ${currentLevel} but received ${value.length}`
      );
    }
    const entries: EIP712ImplementationEntry[] = [
      { type: "array", size: value.length },
    ];
    value.forEach((element) => {
      entries.push(
        ...encodeField(
          metaMap,
          {
            ...field,
            arrayLevels: rest,
          },
          element
        )
      );
    });
    return entries;
  }

  if (field.kind === "custom") {
    if (!field.structName || typeof value !== "object" || value === null) {
      throw new Error(
        `Field ${field.name} expected struct ${field.structName}`
      );
    }
    return encodeStruct(
      metaMap,
      field.structName,
      value as Record<string, unknown>
    );
  }

  const buffer = encodePrimitiveValue(field.kind, field.size, value);
  const entry: EIP712ImplementationEntry = {
    type: "field",
    value: buffer,
  };
  return [entry];
}

function encodePrimitiveValue(
  kind: EIP712FieldKind,
  size: number | undefined,
  value: unknown
): Buffer {
  switch (kind) {
    case "int":
    case "uint": {
      if (typeof size !== "number") {
        throw new Error(`${kind} requires a size`);
      }
      return encodeInteger(value, size * 8);
    }
    case "address":
      return encodeFixedHex(value, 20);
    case "bool":
      return encodeBoolean(value);
    case "string":
      if (value == null) return Buffer.alloc(0);
      if (typeof value !== "string") {
        throw new Error("String value must be a string");
      }
      return Buffer.from(value, "utf8");
    case "fixed-bytes":
      if (typeof size !== "number") {
        throw new Error("fixed-bytes requires a size");
      }
      return encodeFixedHex(value, size);
    case "dynamic-bytes":
      return encodeDynamicHex(value);
    default:
      throw new Error(`Unsupported primitive type: ${kind}`);
  }
}

function padHexString(str: string): string {
  return str.length % 2 ? "0" + str : str;
}

function hexBuffer(str: string): Buffer {
  if (!str) return Buffer.alloc(0);
  const withoutPrefix = str.startsWith("0x") ? str.slice(2) : str;
  return Buffer.from(padHexString(withoutPrefix), "hex");
}

function encodeInteger(value: unknown, sizeInBits = 256): Buffer {
  const failSafeValue = value ?? "0";
  if (typeof failSafeValue === "string" && failSafeValue.startsWith("0x")) {
    return hexBuffer(failSafeValue);
  }

  let numericValue: bigint;
  if (typeof failSafeValue === "string") {
    numericValue = BigInt(failSafeValue);
  } else if (typeof failSafeValue === "number") {
    if (!Number.isSafeInteger(failSafeValue)) {
      throw new Error("Unsafe integer number; use string or bigint");
    }
    numericValue = BigInt(failSafeValue);
  } else if (typeof failSafeValue === "bigint") {
    numericValue = failSafeValue;
  } else if (typeof failSafeValue === "boolean") {
    numericValue = failSafeValue ? 1n : 0n;
  } else {
    throw new Error(
      "Integer value must be a number, bigint, boolean or string"
    );
  }

  if (numericValue < 0n) {
    const modulus = 1n << BigInt(sizeInBits);
    numericValue = (modulus + (numericValue % modulus)) % modulus;
  }

  const hex = padHexString(numericValue.toString(16));
  return Buffer.from(hex, "hex");
}

function encodeFixedHex(value: unknown, byteLength: number): Buffer {
  if (value == null) return Buffer.alloc(0);
  if (typeof value !== "string") {
    throw new Error("Expected hex string value");
  }
  return hexBuffer(value).subarray(0, byteLength);
}

function encodeDynamicHex(value: unknown): Buffer {
  if (value == null) return Buffer.alloc(0);
  if (typeof value !== "string") {
    throw new Error("Dynamic bytes must be a hex string");
  }
  return hexBuffer(value);
}

function encodeBoolean(value: unknown): Buffer {
  return encodeInteger(value, 256);
}
