import { defineHandler } from 'nitro';
import { store } from '../../utils/core';
import { orgHeader } from '../../utils/enterprise';

export default defineHandler((event) => ({
  webhooks: store.listWebhooks(orgHeader(event)).map(({ secret: _s, ...rest }) => rest),
}));
