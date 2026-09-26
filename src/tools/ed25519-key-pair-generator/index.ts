import { Key } from '@vicons/tabler';
import { defineTool } from '../tool';
import { translate } from '@/plugins/i18n.plugin';

export const tool = defineTool({
  name: translate('tools.ed25519-key-pair-generator.title'),
  path: '/ed25519-key-pair-generator',
  description: translate('tools.ed25519-key-pair-generator.description'),
  keywords: ['ed25519', 'key', 'pair', 'generator', 'public', 'private', 'secret', 'ssh', 'openssh', 'curve25519', 'rfc8032', 'pkcs8', 'spki'],
  component: () => import('./ed25519-key-pair-generator.vue'),
  icon: Key,
});
