/**
 * "Was this made by AI?" for a picture or video, without running any AI model.
 *
 * Most AI image and video tools now label what they make: Content Credentials (C2PA) from
 * OpenAI, Google, Adobe, Microsoft and others, the IPTC "trained algorithmic media" code that
 * Google, Meta and Midjourney write, generator names in the file's metadata, and the settings
 * block Stable Diffusion tools leave in PNGs. Hashling reads the file's bytes for those labels.
 * Labels can be stripped (screenshots and most social apps remove them), so "no label" never
 * means "real": the result says so.
 */
import { openSync, readSync, fstatSync, closeSync } from 'node:fs';

export interface MediaVerdict { verdict: 'ai' | 'edited' | 'none'; signs: string[]; camera: string | null; credentials: boolean; note: string }

const MARKERS: [RegExp, string, 'ai' | 'edited'][] = [
  [/digitalsourcetype\/trainedAlgorithmicMedia/i, 'Labelled as made by AI (IPTC “trained algorithmic media”)', 'ai'],
  [/digitalsourcetype\/compositeWithTrainedAlgorithmicMedia/i, 'Labelled as partly made or edited with AI', 'edited'],
  [/digitalsourcetype\/algorithmicMedia/i, 'Labelled as computer-generated', 'ai'],
  [/c2pa\.(created|placed|edited)[\s\S]{0,400}?trainedAlgorithmicMedia/i, 'Content Credentials say an AI tool created it', 'ai'],
  [/DALL[·-]?E|ChatGPT|OpenAI(?! Inc\. ?\(website\))/i, 'Made with OpenAI (ChatGPT or DALL·E)', 'ai'],
  [/Midjourney/i, 'Made with Midjourney', 'ai'],
  [/Stable[ -]?Diffusion|ComfyUI|AUTOMATIC1111|Steps: \d+, Sampler:/i, 'Made with Stable Diffusion', 'ai'],
  [/Adobe Firefly|Generative (Fill|Expand)/i, 'Made or edited with Adobe Firefly', 'edited'],
  [/Made with Google AI|Google (Imagen|Gemini)|SynthID|Nano Banana/i, 'Made with Google AI', 'ai'],
  [/Bing Image Creator|Microsoft Designer|Copilot Designer/i, 'Made with Microsoft’s AI image tools', 'ai'],
  [/\b(Ideogram|Leonardo\.Ai|RunwayML|Runway Gen-\d|OpenAI Sora|Google Veo|Kling AI|Pika Labs|FLUX\.1|Black Forest Labs|Grok Imagine)\b/i, 'Names an AI image or video generator', 'ai'],
  [/Meta AI|Imagined with AI|AI Info/i, 'Labelled “made with AI” by Meta', 'ai'],
];
const CAMERA = /\b(Apple|Canon|NIKON|SONY|FUJIFILM|Panasonic|OLYMPUS|Google|samsung)\0{0,3}((iPhone|Canon|NIKON|ILCE|DSC|X-|DC-|E-M|Pixel|SM-)[\x20-\x7e]{1,30})/;

/** Read the start and the end of a file: metadata lives at one end or the other. */
function sample(path: string): Buffer {
  const fd = openSync(path, 'r');
  try {
    const size = fstatSync(fd).size;
    const head = Buffer.alloc(Math.min(size, 4 * 1024 * 1024));
    readSync(fd, head, 0, head.length, 0);
    if (size <= head.length) return head;
    const tail = Buffer.alloc(Math.min(size - head.length, 2 * 1024 * 1024));
    readSync(fd, tail, 0, tail.length, size - tail.length);
    return Buffer.concat([head, tail]);
  } finally { closeSync(fd); }
}

export function checkMedia(path: string): MediaVerdict {
  // latin1 keeps every byte. Only readable runs of text are searched, so compressed picture
  // data that happens to spell a short name is never mistaken for a label.
  const raw = sample(path).toString('latin1');
  const text = (raw.match(/[\x20-\x7e]{6,}/g) ?? []).join('\n');
  const signs: string[] = [];
  let verdict: MediaVerdict['verdict'] = 'none';
  for (const [re, label, kind] of MARKERS) {
    if (!re.test(text) || signs.includes(label)) continue;
    signs.push(label);
    if (kind === 'ai' || verdict === 'none') verdict = kind === 'ai' ? 'ai' : verdict === 'ai' ? 'ai' : 'edited';
  }
  const credentials = /\bc2pa\b/i.test(text);
  const cam = CAMERA.exec(raw);
  const camera = cam ? `${cam[1]} ${cam[2]}`.replace(/\s+/g, ' ').trim() : null;
  const note = verdict === 'ai' ? 'This file carries a label that an AI tool made it. Treat what it shows as made up unless the person who sent it says otherwise.'
    : verdict === 'edited' ? 'This file says parts of it were made or changed with AI. The rest may be real.'
    : `I found no AI label${camera ? `, and it has camera details (${camera})` : ''}. That does not prove it is real: screenshots, WhatsApp and most social apps strip labels, and camera details can be faked.`;
  return { verdict, signs, camera, credentials, note };
}
