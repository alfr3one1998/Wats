import test from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  createCsv,
  getContact,
  getContacts,
  getStats,
  openDatabase,
  saveInboundMessage,
  signatureIsValid,
  webhookMessages
} from '../server.js';

async function withDatabase(t) {
  const folder = await mkdtemp(join(tmpdir(), 'wats-test-'));
  const db = openDatabase(join(folder, 'customers.sqlite'));
  t.after(async () => {
    db.close();
    await rm(folder, { recursive: true, force: true });
  });
  return db;
}

function incomingWebhook() {
  return {
    object: 'whatsapp_business_account',
    entry: [
      {
        changes: [
          {
            field: 'messages',
            value: {
              contacts: [{ wa_id: '966512345678', profile: { name: 'أم أحمد' } }],
              messages: [
                {
                  from: '966512345678',
                  id: 'wamid.test.1',
                  timestamp: '1791243000',
                  type: 'text',
                  text: { body: 'السلام عليكم، أبغى كيكة.' }
                }
              ]
            }
          }
        ]
      }
    ]
  };
}

test('parses, stores and de-duplicates inbound WhatsApp messages', async (t) => {
  const db = await withDatabase(t);
  const [incoming] = webhookMessages(incomingWebhook());

  assert.equal(incoming.phone, '966512345678');
  assert.equal(incoming.whatsappName, 'أم أحمد');
  assert.equal(incoming.body, 'السلام عليكم، أبغى كيكة.');
  assert.equal(saveInboundMessage(db, incoming), true);
  assert.equal(saveInboundMessage(db, incoming), false, 'Meta retry must not count the same message twice');

  const contact = getContact(db, incoming.phone);
  assert.equal(contact.display_name, 'أم أحمد');
  assert.equal(contact.total_messages, 1);
  assert.equal(contact.last_message_preview, 'السلام عليكم، أبغى كيكة.');
  assert.equal(getStats(db).contacts, 1);
  assert.equal(getStats(db).messages, 1);
});

test('searches contacts, keeps custom names and exports CSV safely', async (t) => {
  const db = await withDatabase(t);
  const [incoming] = webhookMessages(incomingWebhook());
  saveInboundMessage(db, incoming);
  db.prepare('UPDATE contacts SET custom_name = ?, labels = ? WHERE phone = ?').run(
    '=أم أحمد — زبونة كيك',
    JSON.stringify(['عميل دائم', 'كيك']),
    incoming.phone
  );

  const [contact] = getContacts(db, { query: 'زبونة', filter: 'named' });
  assert.equal(contact.display_name, '=أم أحمد — زبونة كيك');
  assert.deepEqual(contact.labels, ['عميل دائم', 'كيك']);
  const csv = createCsv([contact]);
  assert.match(csv, /"'=أم أحمد — زبونة كيك"/, 'CSV formula values are escaped');
  assert.match(csv, /"'\+966512345678"/, 'Phone values are protected from spreadsheet formula parsing');
});

test('validates the Meta signature with a constant-time comparison', () => {
  const raw = Buffer.from('{"object":"whatsapp_business_account"}');
  const secret = 'meta-app-secret';
  const signature = `sha256=${createHmac('sha256', secret).update(raw).digest('hex')}`;

  assert.equal(signatureIsValid(raw, signature, secret), true);
  assert.equal(signatureIsValid(raw, 'sha256=not-valid', secret), false);
  assert.equal(signatureIsValid(raw, signature, ''), false);
});
