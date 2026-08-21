import { KALI } from "./tp-member.js";

export function articleId(url: string) {
  const m = /(LEGIARTI\w+)(\W|$)/.exec(url);
  return m ? m[1] : KALI;
}

export function sectionId(url: string) {
  return new RegExp("(LEGISCTA\\w+)").exec(url);
}
