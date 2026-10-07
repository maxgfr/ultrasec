import type { Pack } from "../types.js";
import { COMMON_PACK } from "./common.js";
import { NODE_PACKS } from "./node.js";
import { PYTHON_PACKS } from "./python.js";
import { JAVA_PACKS } from "./java.js";
import { GO_PACKS } from "./go.js";
import { RUBY_PACKS } from "./ruby.js";
import { PHP_PACKS } from "./php.js";

/** Every pack the engine applies, in a stable order: language-agnostic first,
 *  then each ecosystem's own pack before its frameworks'. */
export const PACKS: Pack[] = [COMMON_PACK, ...NODE_PACKS, ...PYTHON_PACKS, ...JAVA_PACKS, ...GO_PACKS, ...RUBY_PACKS, ...PHP_PACKS];
