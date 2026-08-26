import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const serverPath = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [serverPath],
});
const client = new Client({ name: "tool-annotations-test", version: "1.0.0" });

try {
  await client.connect(transport);
  const { tools } = await client.listTools();
  const missingAnnotations = tools.filter((tool) => !tool.annotations).map((tool) => tool.name);
  const readOnly = tools.filter((tool) => tool.annotations?.readOnlyHint);
  const additiveMutating = tools.filter(
    (tool) => tool.annotations?.readOnlyHint === false && !tool.annotations?.destructiveHint,
  );
  const destructive = tools.filter((tool) => tool.annotations?.destructiveHint);

  assert.equal(tools.length, 54);
  assert.deepEqual(missingAnnotations, []);
  assert.equal(readOnly.length, 37);
  assert.deepEqual(
    additiveMutating.map((tool) => tool.name).sort(),
    ["make_function_at", "select_binary"],
  );
  assert.deepEqual(
    destructive.map((tool) => tool.name).sort(),
    [
      "declare_c_type",
      "define_types",
      "delete_comment",
      "delete_function_comment",
      "format_value",
      "patch_bytes",
      "rename_data",
      "rename_function",
      "rename_multi_variables",
      "rename_single_variable",
      "retype_variable",
      "set_comment",
      "set_function_comment",
      "set_function_prototype",
      "set_local_variable_type",
    ],
  );
  assert.equal(tools.find((tool) => tool.name === "patch_bytes")?.annotations?.idempotentHint, true);
} finally {
  await client.close();
}
