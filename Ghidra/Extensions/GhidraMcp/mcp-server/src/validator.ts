import type { McpTool, JsonSchema } from "./tools";

type JsonObject = Record<string, unknown>;

export function validateToolArguments(tool: McpTool, args: JsonObject): string[] {
  return validateSchema(tool.inputSchema, args, "");
}

function validateSchema(schema: JsonSchema, value: unknown, path: string): string[] {
  const errors: string[] = [];
  if (schema.anyOf && Array.isArray(schema.anyOf)) {
    const matched = schema.anyOf.some(candidate => validateSchema(candidate as JsonSchema, value, path).length === 0);
    if (!matched) {
      errors.push(`${prefix(path)}must match one required argument shape`);
    }
  }

  if (schema.type === "object") {
    if (!isPlainObject(value)) {
      return [`${prefix(path)}must be an object`];
    }
    const properties = isPlainObject(schema.properties) ? schema.properties : {};
    const required = Array.isArray(schema.required) ? schema.required : [];
    for (const name of required) {
      if (typeof name === "string" && !(name in value)) {
        errors.push(`Missing required property: ${path ? `${path}.` : ""}${name}`);
      }
    }
    if (schema.additionalProperties === false) {
      for (const name of Object.keys(value)) {
        if (!(name in properties)) {
          errors.push(`Unknown property: ${path ? `${path}.` : ""}${name}`);
        }
      }
    }
    for (const [name, propertySchema] of Object.entries(properties)) {
      if (name in value) {
        errors.push(...validateSchema(propertySchema as JsonSchema, value[name], path ? `${path}.${name}` : name));
      }
    }
  }
  else if (schema.type === "string" && typeof value !== "string") {
    errors.push(`${prefix(path)}must be a string`);
  }
  else if (schema.type === "integer") {
    if (!Number.isInteger(value)) {
      errors.push(`${prefix(path)}must be an integer`);
    }
    else {
      const numberValue = value as number;
      if (typeof schema.minimum === "number" && numberValue < schema.minimum) {
        errors.push(`${prefix(path)}must be >= ${schema.minimum}`);
      }
      if (typeof schema.maximum === "number" && numberValue > schema.maximum) {
        errors.push(`${prefix(path)}must be <= ${schema.maximum}`);
      }
    }
  }
  else if (schema.type === "array") {
    if (!Array.isArray(value)) {
      errors.push(`${prefix(path)}must be an array`);
    }
    else if (schema.items) {
      value.forEach((item, index) => {
        errors.push(...validateSchema(schema.items as JsonSchema, item, `${path}[${index}]`));
      });
    }
  }

  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
    errors.push(`${prefix(path)}must be one of ${schema.enum.join(", ")}`);
  }
  return errors;
}

function isPlainObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function prefix(path: string): string {
  return path ? `${path} ` : "Value ";
}
