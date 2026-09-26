<script setup lang="ts">
import { ref } from 'vue';
import { computedAsync } from '@vueuse/core';
import {
  type Ed25519KeyPair,
  base64ToBytes,
  generateEd25519KeyPair,
  hexToBytes,
} from './ed25519-key-pair-generator.service';
import TextareaCopyable from '@/components/TextareaCopyable.vue';
import InputCopyable from '@/components/InputCopyable.vue';
import { useValidation } from '@/composable/validation';

const comment = ref('id_ed25519');
const seedMode = ref<'Random' | 'Custom seed'>('Random');
const customSeed = ref('');
const outputFormat = ref<'OpenSSH' | 'PEM (PKCS#8 / SPKI)' | 'Raw (Hex / Base64)'>('OpenSSH');
const refreshCounter = ref(0);

function refreshKeyPair() {
  refreshCounter.value++;
}

const seedValidation = useValidation({
  source: customSeed,
  rules: [
    {
      message: 'Seed must be 32 bytes (64 hex characters or Base64 decoding to 32 bytes)',
      validator: (val: string) => {
        if (!val || val.trim() === '') {
          return false;
        }
        const trimmed = val.trim();
        if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
          return true;
        }
        try {
          const bytes = base64ToBytes(trimmed);
          return bytes.length === 32;
        }
        catch {
          return false;
        }
      },
    },
  ],
});

const emptyKeyPair: Ed25519KeyPair = {
  publicKeyOpenSSH: '',
  privateKeyOpenSSH: '',
  publicKeyPem: '',
  privateKeyPem: '',
  publicKeyHex: '',
  privateKeyHex: '',
  publicKeyBase64: '',
  privateKeyBase64: '',
  fingerprintSha256: '',
  fingerprintMd5: '',
};

const keyPair = computedAsync(async () => {
  // Trigger update on refresh button click
  if (refreshCounter.value < 0) {
    return emptyKeyPair;
  }

  try {
    let seedBytes: Uint8Array | undefined;
    if (seedMode.value === 'Custom seed') {
      const trimmed = customSeed.value.trim();
      if (!trimmed) {
        return emptyKeyPair;
      }
      if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
        seedBytes = hexToBytes(trimmed);
      }
      else {
        seedBytes = base64ToBytes(trimmed);
      }
      if (seedBytes.length !== 32) {
        return emptyKeyPair;
      }
    }

    return await generateEd25519KeyPair({
      seed: seedBytes,
      comment: comment.value.trim() || undefined,
    });
  }
  catch {
    return emptyKeyPair;
  }
}, emptyKeyPair);

function getBaseFilename() {
  const c = comment.value.trim();
  if (!c) {
    return 'id_ed25519';
  }
  return c.replace(/[/\\?%*:|"<>]/g, '_');
}

function downloadFile(content: string, filename: string) {
  if (!content) {
    return;
  }
  const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
</script>

<template>
  <div style="flex: 0 0 100%" flex flex-col gap-4>
    <c-card>
      <div flex flex-col gap-3>
        <div flex flex-wrap items-center gap-3>
          <c-input-text
            v-model:value="comment"
            label="Key comment (optional):"
            placeholder="e.g. id_ed25519 or user@host"
            clearable
            flex-1
          />

          <c-buttons-select
            v-model:value="seedMode"
            :options="['Random', 'Custom seed']"
            label="Seed mode:"
          />

          <div flex items-end pt-5>
            <c-button @click="refreshKeyPair">
              Refresh key-pair
            </c-button>
          </div>
        </div>

        <div v-if="seedMode === 'Custom seed'">
          <c-input-text
            v-model:value="customSeed"
            label="32-byte Seed (64 Hex or 44 Base64 characters):"
            placeholder="e.g. 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
            clearable
            monospace
            :validation="seedValidation"
          />
        </div>
      </div>
    </c-card>

    <div flex items-center justify-between>
      <c-buttons-select
        v-model:value="outputFormat"
        :options="['OpenSSH', 'PEM (PKCS#8 / SPKI)', 'Raw (Hex / Base64)']"
        label="Format:"
      />
    </div>

    <!-- OpenSSH Format -->
    <div v-if="outputFormat === 'OpenSSH'" flex flex-col gap-4>
      <div>
        <div flex items-center justify-between mb-2>
          <h3 m-0>
            Public key (OpenSSH)
          </h3>
          <c-button size="small" @click="downloadFile(keyPair.publicKeyOpenSSH, `${getBaseFilename()}.pub`)">
            Download .pub
          </c-button>
        </div>
        <TextareaCopyable :value="keyPair.publicKeyOpenSSH" />
      </div>

      <div>
        <div flex items-center justify-between mb-2>
          <h3 m-0>
            Private key (OpenSSH)
          </h3>
          <c-button size="small" @click="downloadFile(keyPair.privateKeyOpenSSH, getBaseFilename())">
            Download private key
          </c-button>
        </div>
        <TextareaCopyable :value="keyPair.privateKeyOpenSSH" />
      </div>
    </div>

    <!-- PEM Format -->
    <div v-else-if="outputFormat === 'PEM (PKCS#8 / SPKI)'" flex flex-col gap-4>
      <div>
        <div flex items-center justify-between mb-2>
          <h3 m-0>
            Public key (SPKI PEM)
          </h3>
          <c-button size="small" @click="downloadFile(keyPair.publicKeyPem, `${getBaseFilename()}.pub.pem`)">
            Download public.pem
          </c-button>
        </div>
        <TextareaCopyable :value="keyPair.publicKeyPem" />
      </div>

      <div>
        <div flex items-center justify-between mb-2>
          <h3 m-0>
            Private key (PKCS#8 PEM)
          </h3>
          <c-button size="small" @click="downloadFile(keyPair.privateKeyPem, `${getBaseFilename()}.pem`)">
            Download private.pem
          </c-button>
        </div>
        <TextareaCopyable :value="keyPair.privateKeyPem" />
      </div>
    </div>

    <!-- Raw (Hex / Base64) Format -->
    <div v-else flex flex-col gap-4>
      <c-card title="Hex (32 bytes / 64 characters)">
        <div flex flex-col gap-3>
          <InputCopyable
            :value="keyPair.publicKeyHex"
            label="Public key (Hex):"
            readonly
            monospace
          />
          <InputCopyable
            :value="keyPair.privateKeyHex"
            label="Private key seed (Hex):"
            readonly
            monospace
          />
        </div>
      </c-card>

      <c-card title="Base64 (32 bytes / 44 characters)">
        <div flex flex-col gap-3>
          <InputCopyable
            :value="keyPair.publicKeyBase64"
            label="Public key (Base64):"
            readonly
            monospace
          />
          <InputCopyable
            :value="keyPair.privateKeyBase64"
            label="Private key seed (Base64):"
            readonly
            monospace
          />
        </div>
      </c-card>
    </div>

    <!-- Fingerprints Section -->
    <c-card title="Fingerprints (OpenSSH)">
      <div flex flex-col gap-3>
        <InputCopyable
          :value="keyPair.fingerprintSha256"
          label="SHA256 (OpenSSH format):"
          readonly
          monospace
        />
        <InputCopyable
          :value="keyPair.fingerprintMd5"
          label="MD5 (Legacy format):"
          readonly
          monospace
        />
      </div>
    </c-card>
  </div>
</template>
