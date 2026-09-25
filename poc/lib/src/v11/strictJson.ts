/** Strict UTF-8/I-JSON parsing with duplicate-member detection before JSON.parse. */
export function strictJson(body: Buffer): Record<string, unknown> {
  if (body.length > 65536) throw new Error("JSON size limit exceeded");
  const source = new TextDecoder("utf-8", {fatal:true}).decode(body);
  let i=0;
  const ws=()=>{while(/[\t\n\r ]/.test(source[i] ?? "x")) i++;};
  function string(): string {
    const start=i++;
    while(i<source.length) {
      if(source[i] === '"') {i++;return JSON.parse(source.slice(start,i)) as string;}
      if(source[i] === '\\') i++;
      i++;
    }
    throw new Error("unterminated string");
  }
  function value(depth: number): void {
    if(depth>64) throw new Error("JSON nesting limit exceeded");
    ws();const c=source[i];
    if(c === '{') {
      i++;ws();const keys=new Set<string>();
      if(source[i] === '}') {i++;return;}
      while(true) {
        ws();if(source[i] !== '"') throw new Error("expected member");
        const key=string();if(keys.has(key)) throw new Error("duplicate JSON member");keys.add(key);
        ws();if(source[i++] !== ':') throw new Error("expected colon");value(depth+1);ws();
        const end=source[i++];if(end === '}') return;if(end !== ',') throw new Error("expected comma");
      }
    }
    if(c === '[') {
      i++;ws();if(source[i] === ']') {i++;return;}
      while(true) {value(depth+1);ws();const end=source[i++];if(end === ']') return;if(end !== ',') throw new Error("expected comma");}
    }
    if(c === '"') {string();return;}
    const token=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(source.slice(i));
    if(!token) throw new Error("invalid JSON token");i+=token[0].length;
  }
  value(0);ws();if(i !== source.length) throw new Error("trailing JSON data");
  const result: unknown=JSON.parse(source);
  function inspect(v: unknown): void {
    if(typeof v === 'number' && (!Number.isFinite(v) || (Number.isInteger(v) && !Number.isSafeInteger(v)))) throw new Error("unsafe JSON number");
    if(typeof v === 'string' && /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(v)) throw new Error("unpaired surrogate");
    if(v && typeof v === 'object') for(const [k,x] of Object.entries(v)) {inspect(k);inspect(x);}
  }
  inspect(result);
  if(!result || typeof result !== 'object' || Array.isArray(result)) throw new Error("expected JSON object");
  return result as Record<string, unknown>;
}
