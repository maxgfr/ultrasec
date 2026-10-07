import type { Pack } from "../types.js";
import { COMMON_PACK } from "./common.js";
import { NODE_PACKS } from "./node.js";
import { PYTHON_PACKS } from "./python.js";

/** Every pack the engine applies, in a stable order. */
export const PACKS: Pack[] = [COMMON_PACK, ...NODE_PACKS, ...PYTHON_PACKS];
