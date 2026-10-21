/**
 * Scam red flags anyone can spot in a message, checked on this Mac without sending the text anywhere.
 * Shared by the dashboard's Scam check and the MCP scam_check tool.
 */
const SHORTENERS = /^(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly|rb\.gy|ow\.ly|buff\.ly|shorturl\.at|tiny\.cc|rebrand\.ly|s\.id|t\.ly)$/i;
const ODD_TLDS = /\.(top|xyz|click|zip|mov|icu|shop|support|live|rest|cam|sbs|cfd|lol|quest|monster|buzz|gq|tk|ml|cf|info|biz|vip|bond|win|club)$/i;
/** Brands scammers copy most, and the real domains they use. */
const BRANDS: Record<string, RegExp> = {
  apple: /(^|\.)(apple\.com|icloud\.com)$/, paypal: /(^|\.)paypal\.com$/, amazon: /(^|\.)(amazon\.[a-z.]+|amzn\.to)$/, microsoft: /(^|\.)(microsoft\.com|live\.com|office\.com|outlook\.com)$/,
  netflix: /(^|\.)netflix\.com$/, dhl: /(^|\.)dhl\.[a-z.]+$/, fedex: /(^|\.)fedex\.com$/, usps: /(^|\.)usps\.com$/, ups: /(^|\.)ups\.com$/, royalmail: /(^|\.)royalmail\.com$/,
  google: /(^|\.)(google\.[a-z.]+|youtube\.com)$/, facebook: /(^|\.)(facebook\.com|fb\.com|meta\.com)$/, instagram: /(^|\.)instagram\.com$/, whatsapp: /(^|\.)whatsapp\.com$/,
  coinbase: /(^|\.)coinbase\.com$/, binance: /(^|\.)binance\.com$/,
};
/** How each brand writes its own name; the rest just get a capital first letter. */
const BRAND_NAMES: Record<string, string> = { paypal: 'PayPal', dhl: 'DHL', fedex: 'FedEx', usps: 'USPS', ups: 'UPS', royalmail: 'Royal Mail', whatsapp: 'WhatsApp' };

/** Red flags anyone can spot, found on this Mac without sending the text anywhere. */
export function redFlags(text: string): { label: string; why: string }[] {
  const t = text.toLowerCase();
  const flags: { label: string; why: string }[] = [];
  const add = (label: string, why: string) => flags.push({ label, why });
  const hosts = [...text.matchAll(/\b(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:\/[^\s]*)?/gi)].map((m) => m[1].toLowerCase()).filter((h) => !/\.(png|jpe?g|gif|pdf)$/.test(h));
  const ipLink = /https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(text);
  for (const h of new Set(hosts)) {
    if (SHORTENERS.test(h)) add(`Hidden link (${h})`, 'Short links hide where they really go. Scammers use them so you cannot see the fake website.');
    if (h.startsWith('xn--') || h.includes('.xn--')) add(`Look-alike letters in ${h}`, 'This web address uses special characters that look like normal letters, a trick to copy a real company’s name.');
    if (ODD_TLDS.test(h)) add(`Unusual web address (${h})`, 'Real banks and big companies almost never use endings like this. Cheap endings are popular for throwaway scam sites.');
    for (const [brand, real] of Object.entries(BRANDS)) {
      if (h.replace(/[^a-z]/g, '').includes(brand) && !real.test(h)) { const B = BRAND_NAMES[brand] ?? brand[0].toUpperCase() + brand.slice(1); add(`Fake ${B} address (${h})`, `It mentions ${B} but is not ${B}’s real website.`); }
    }
  }
  if (ipLink) add('Link to a bare number address', 'Real companies use names, not numbers like 123.45.67.89, for their websites.');
  const has = (re: RegExp) => re.test(t);
  if (has(/\b(urgent|immediately|within 24 hours|within 48 hours|final (notice|warning)|act now|last chance|expires? today|suspend(ed)?|locked|deactivat)/)) add('Rushes you', 'Scams create panic so you act before thinking. Real companies give you time.');
  if (has(/\b(gift ?cards?|itunes card|google play card|steam card|bitcoin|crypto|usdt|wire transfer|western union|moneygram|zelle)\b/)) add('Asks for gift cards, crypto or a money transfer', 'No real company, government or bank asks to be paid this way. Money sent like this cannot be recovered.');
  if (has(/\b(verify|confirm|update) (your )?(account|identity|password|payment|details|information)|one[- ]time (code|password)|\botp\b|security code|verification code/)) add('Asks for passwords or codes', 'Never share a password or a code sent to your phone. Real staff never ask for them.');
  if (has(/\b(anydesk|teamviewer|remote (access|support|desktop)|screen ?share|quick ?assist|install (this|the) (app|software))\b/)) add('Wants to control your computer', 'Asking you to install a remote-control app is the main step in tech-support scams.');
  if (has(/\b(you('ve| have)? won|winner|prize|lottery|inheritance|claim your (reward|refund|prize)|unclaimed)\b/)) add('Too good to be true', 'Prizes you never entered and surprise refunds are bait to get your details or a “fee”.');
  if (has(/\b(tolls?|e-?z ?pass|fastrak|sunpass|txtag|peach ?pass|i-?pass|turnpike|good to go)\b/) && has(/\b(unpaid|outstanding|balance|overdue|late fee|fine|pay)\b/)) add('Unpaid toll text', 'Texts about unpaid tolls are one of the most common scams right now. Toll agencies do not text you a link to pay. Check your balance in the agency’s own app or website.');
  if (has(/\b(parcel|package|delivery|shipment)\b/) && has(/\b(fee|pay|failed|attempt|reschedule|customs|address)\b/)) add('Delivery fee or failed delivery', 'Fake delivery texts are the most common scam. Couriers do not text links to pay small fees.');
  if (has(/\b(virus|infected|hacked|trojan|security alert|your (computer|mac|iphone) (is|has))\b/) && has(/\b(call|phone|contact|support)\b/)) add('Fake virus warning', 'Real virus warnings never show a phone number to call. That number reaches scammers.');
  if (has(/(\+?\d[\d\s().-]{8,}\d)/) && has(/\b(call|phone|contact|support|helpline)\b/)) add('Gives a number to call', 'Only call numbers you look up yourself, like the one on your bank card. Numbers in messages can reach scammers.');
  if (has(/\b(irs|hmrc|tax refund|police|warrant|arrest|court|fine)\b/)) add('Pretends to be the government or police', 'Tax offices and police do not threaten arrest by text or email, and never ask for payment by link.');
  if (has(/\b(mom|mum|dad|it'?s me|new (number|phone))\b/) && has(/\b(money|pay|transfer|bill|urgent|help)\b/)) add('“Hi Mum, new number” style message', 'Scammers pretend to be your child or friend on a new number. Call the old number to check.');
  return flags;
}

