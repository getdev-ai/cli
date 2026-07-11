// must NOT fire: Slack/SendGrid/Twilio near-misses.
const slackWrongLetter = "xoxz-FAKEFAKEFA"; // "z" is not in [baprs]
const slackTooShort = "xoxb-FAKEFAKEF";

const sendgridSingleSegment = "SG.FAKEFAKEFAKEFAKE";
const sendgridSegmentsTooShort = "SG.FAKEFAKEFAKEFAK.FAKEFAKEFAKEFAKE";

const twilioTooShort = "SKdeadbeefdeadbeefdeadbeefdeadbee";
const twilioUppercaseHex = "SKDEADBEEFDEADBEEFDEADBEEFDEADBEEF";
