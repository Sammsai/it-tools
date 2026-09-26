<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue';
import {
  formatTimestamp,
  generateJwtFromParts,
  getClaimsList,
  parseJwt,
  splitJwt,
  verifyJwtSignature,
} from './jwt-parser.service';
import { useCopy } from '@/composable/copy';

const DEFAULT_HS256 = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
const DEFAULT_SECRET = 'your-256-bit-secret';

const rawJwt = ref(DEFAULT_HS256);
const headerJson = ref('');
const payloadJson = ref('');
const secret = ref(DEFAULT_SECRET);
const secretIsBase64 = ref(false);
const showClaimsTable = ref(false);

const { copy: copyFullToken } = useCopy({ source: rawJwt, text: 'Token copied to clipboard!' });
const { copy: copyHeader } = useCopy({ source: headerJson, text: 'Header JSON copied!' });
const { copy: copyPayload } = useCopy({ source: payloadJson, text: 'Payload JSON copied!' });

let isSyncing = false;

function updateDecodedFromEncoded(jwt: string) {
  if (isSyncing) {
    return;
  }
  isSyncing = true;

  const parsed = parseJwt(jwt);
  if (parsed) {
    headerJson.value = parsed.headerRaw;
    payloadJson.value = parsed.payloadRaw;
  }

  nextTick(() => {
    isSyncing = false;
  });
}

function updateEncodedFromDecoded() {
  if (isSyncing) {
    return;
  }
  isSyncing = true;

  const generated = generateJwtFromParts({
    headerJson: headerJson.value,
    payloadJson: payloadJson.value,
    secret: secret.value,
    secretIsBase64: secretIsBase64.value,
  });

  if (generated) {
    rawJwt.value = generated;
  }

  nextTick(() => {
    isSyncing = false;
  });
}

// Initial sync
updateDecodedFromEncoded(rawJwt.value);

watch(rawJwt, (val) => {
  updateDecodedFromEncoded(val);
});

watch([headerJson, payloadJson, secret, secretIsBase64], () => {
  updateEncodedFromDecoded();
});

const tokenParts = computed(() => splitJwt(rawJwt.value));
const parsedJwt = computed(() => parseJwt(rawJwt.value));

const verificationResult = computed(() => {
  return verifyJwtSignature({
    jwt: rawJwt.value,
    secret: secret.value,
    secretIsBase64: secretIsBase64.value,
  });
});

const algorithm = computed(() => parsedJwt.value?.alg || 'HS256');

const payloadClaims = computed(() => {
  if (!parsedJwt.value) {
    return [];
  }
  return getClaimsList(parsedJwt.value.payload);
});

const expInfo = computed(() => {
  if (!parsedJwt.value?.payload.exp) {
    return null;
  }
  return formatTimestamp(parsedJwt.value.payload.exp);
});

const iatInfo = computed(() => {
  if (!parsedJwt.value?.payload.iat) {
    return null;
  }
  return formatTimestamp(parsedJwt.value.payload.iat);
});

const nbfInfo = computed(() => {
  if (!parsedJwt.value?.payload.nbf) {
    return null;
  }
  return formatTimestamp(parsedJwt.value.payload.nbf);
});

function loadSample(type: 'hs256' | 'rs256' | 'none') {
  if (type === 'hs256') {
    secret.value = DEFAULT_SECRET;
    secretIsBase64.value = false;
    rawJwt.value = DEFAULT_HS256;
  }
  else if (type === 'rs256') {
    rawJwt.value = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.EkN-DOsnsuRjRO6BxXemmJDm3HbxqumxK9';
  }
  else if (type === 'none') {
    rawJwt.value = 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.';
  }
}

function clearAll() {
  rawJwt.value = '';
  headerJson.value = '';
  payloadJson.value = '';
}
</script>

<template>
  <div style="flex: 0 0 100%" flex flex-col gap-4>
    <!-- Top toolbar -->
    <div flex flex-wrap items-center justify-between gap-3>
      <div flex flex-wrap items-center gap-2>
        <span op-70 text-sm>Samples:</span>
        <c-button size="small" @click="loadSample('hs256')">
          HS256 (HMAC)
        </c-button>
        <c-button size="small" @click="loadSample('rs256')">
          RS256
        </c-button>
        <c-button size="small" @click="loadSample('none')">
          Unsigned (none)
        </c-button>
      </div>

      <div flex items-center gap-2>
        <c-button size="small" @click="copyFullToken()">
          Copy Token
        </c-button>
        <c-button size="small" variant="text" @click="clearAll()">
          Clear
        </c-button>
      </div>
    </div>

    <!-- Main Two-Column Layout (jwt.io style) -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <!-- Left Column: ENCODED -->
      <div flex flex-col gap-4>
        <c-card>
          <div flex flex-col gap-3>
            <div flex items-center justify-between>
              <h3 m-0 font-bold text-base>
                Encoded
              </h3>
              <span text-xs op-60>Paste a token here or edit decoded JSON on the right</span>
            </div>

            <c-input-text
              v-model:value="rawJwt"
              placeholder="Paste your JWT token here (header.payload.signature)..."
              rows="7"
              multiline
              raw-text
              monospace
            />

            <!-- Color-coded preview (like jwt.io) -->
            <div v-if="tokenParts.isValidFormat" flex flex-col gap-2 mt-2>
              <div text-xs font-bold op-70>
                TOKEN SEGMENTS (COLOR CODED)
              </div>
              <div class="jwt-preview-box">
                <span class="jwt-part-header">{{ tokenParts.headerPart }}</span>
                <span class="jwt-dot">.</span>
                <span class="jwt-part-payload">{{ tokenParts.payloadPart }}</span>
                <span class="jwt-dot">.</span>
                <span class="jwt-part-signature">{{ tokenParts.signaturePart }}</span>
              </div>

              <!-- Color legend -->
              <div flex flex-wrap items-center gap-4 text-xs mt-1>
                <div flex items-center gap-1>
                  <span class="legend-dot bg-#fb015b" />
                  <span text-#fb015b font-bold>HEADER</span>
                </div>
                <div flex items-center gap-1>
                  <span class="legend-dot bg-#d63aff" />
                  <span text-#d63aff font-bold>PAYLOAD</span>
                </div>
                <div flex items-center gap-1>
                  <span class="legend-dot bg-#00b9f1" />
                  <span text-#00b9f1 font-bold>SIGNATURE</span>
                </div>
              </div>
            </div>
          </div>
        </c-card>
      </div>

      <!-- Right Column: DECODED -->
      <div flex flex-col gap-4>
        <!-- 1. HEADER -->
        <c-card class="jwt-card-header">
          <div flex flex-col gap-3>
            <div flex items-center justify-between>
              <div flex items-center gap-2>
                <h3 m-0 font-bold text-base text-#fb015b>
                  HEADER: ALGORITHM & TOKEN TYPE
                </h3>
              </div>
              <div flex items-center gap-2>
                <n-tag size="small" type="error" round :bordered="false">
                  {{ algorithm }}
                </n-tag>
                <c-button size="small" variant="text" @click="copyHeader()">
                  Copy
                </c-button>
              </div>
            </div>

            <c-input-text
              v-model:value="headerJson"
              placeholder="{ &quot;alg&quot;: &quot;HS256&quot;, &quot;typ&quot;: &quot;JWT&quot; }"
              rows="4"
              multiline
              raw-text
              monospace
            />
          </div>
        </c-card>

        <!-- 2. PAYLOAD -->
        <c-card class="jwt-card-payload">
          <div flex flex-col gap-3>
            <div flex items-center justify-between>
              <h3 m-0 font-bold text-base text-#d63aff>
                PAYLOAD: DATA
              </h3>
              <c-button size="small" variant="text" @click="copyPayload()">
                Copy
              </c-button>
            </div>

            <!-- Time status indicators -->
            <div v-if="expInfo || iatInfo || nbfInfo" flex flex-wrap items-center gap-2>
              <n-tag
                v-if="expInfo"
                size="small"
                :type="expInfo.isPast ? 'error' : 'success'"
                round
                :bordered="false"
              >
                {{ expInfo.isPast ? `Expired (${expInfo.relative})` : `Expires (${expInfo.relative})` }}
              </n-tag>

              <n-tag v-if="iatInfo" size="small" type="info" round :bordered="false">
                Issued {{ iatInfo.relative }}
              </n-tag>

              <n-tag v-if="nbfInfo" size="small" type="warning" round :bordered="false">
                Not before {{ nbfInfo.relative }}
              </n-tag>
            </div>

            <c-input-text
              v-model:value="payloadJson"
              placeholder="{ &quot;sub&quot;: &quot;1234567890&quot;, &quot;name&quot;: &quot;John Doe&quot; }"
              rows="7"
              multiline
              raw-text
              monospace
            />

            <!-- Toggle detailed claims view -->
            <div v-if="payloadClaims.length > 0">
              <div flex items-center justify-between cursor-pointer py-1 @click="showClaimsTable = !showClaimsTable">
                <span text-xs font-bold op-70>
                  {{ showClaimsTable ? '▼ Hide standard claims breakdown' : '▶ Show standard claims breakdown' }}
                </span>
                <span text-xs op-50>{{ payloadClaims.length }} claims</span>
              </div>

              <div v-if="showClaimsTable" class="claims-table-wrapper" mt-2>
                <n-table size="small" :bordered="false" :single-line="false">
                  <thead>
                    <tr>
                      <th style="width: 140px">
                        Claim
                      </th>
                      <th>Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="c in payloadClaims" :key="c.claim">
                      <td style="vertical-align: top">
                        <span font-bold>{{ c.claim }}</span>
                        <div v-if="c.description" text-xs op-60>
                          {{ c.description }}
                        </div>
                      </td>
                      <td style="word-break: break-all">
                        <span>{{ c.value }}</span>
                        <div v-if="c.friendlyValue" text-xs text-primary font-bold mt-1>
                          {{ c.friendlyValue }}
                        </div>
                      </td>
                    </tr>
                  </tbody>
                </n-table>
              </div>
            </div>
          </div>
        </c-card>

        <!-- 3. VERIFY SIGNATURE -->
        <c-card class="jwt-card-signature">
          <div flex flex-col gap-3>
            <div flex items-center justify-between>
              <h3 m-0 font-bold text-base text-#00b9f1>
                VERIFY SIGNATURE
              </h3>

              <n-tag
                size="small"
                round
                :bordered="false"
                :type="verificationResult.status === 'valid' ? 'success' : verificationResult.status === 'invalid' ? 'error' : 'warning'"
              >
                {{ verificationResult.message }}
              </n-tag>
            </div>

            <!-- Algorithm signature scheme formula -->
            <div class="signature-formula">
              <span font-mono text-xs op-80>
                {{ algorithm }}(
                <br>
                &nbsp;&nbsp;base64UrlEncode(header) + "." +
                <br>
                &nbsp;&nbsp;base64UrlEncode(payload),
                <br>
                &nbsp;&nbsp;[ your-secret-key ]
                <br>
                )
              </span>
            </div>

            <!-- Secret Key Input -->
            <div v-if="['HS256', 'HS384', 'HS512'].includes(algorithm)" flex flex-col gap-2>
              <c-input-text
                v-model:value="secret"
                label="Secret (HMAC Key):"
                placeholder="your-256-bit-secret"
                clearable
                monospace
              />

              <div flex items-center gap-2 mt-1>
                <n-checkbox v-model:checked="secretIsBase64">
                  Secret base64 encoded
                </n-checkbox>
              </div>
            </div>

            <div v-else text-xs op-70 p-2 rounded bg-gray-50 dark:bg-dark-600>
              {{ verificationResult.message }}
            </div>
          </div>
        </c-card>
      </div>
    </div>
  </div>
</template>

<style lang="less" scoped>
.jwt-card-header {
  border-left: 4px solid #fb015b;
}

.jwt-card-payload {
  border-left: 4px solid #d63aff;
}

.jwt-card-signature {
  border-left: 4px solid #00b9f1;
}

.jwt-preview-box {
  padding: 12px;
  border-radius: 6px;
  font-family: monospace;
  font-size: 13px;
  line-height: 1.6;
  word-break: break-all;
  background-color: rgba(127, 127, 127, 0.08);
  border: 1px solid rgba(127, 127, 127, 0.15);
}

.jwt-part-header {
  color: #fb015b;
  font-weight: 600;
}

.jwt-part-payload {
  color: #d63aff;
  font-weight: 600;
}

.jwt-part-signature {
  color: #00b9f1;
  font-weight: 600;
}

.jwt-dot {
  color: #9e9e9e;
  font-weight: 700;
  margin: 0 1px;
}

.legend-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.signature-formula {
  padding: 8px 12px;
  border-radius: 6px;
  background-color: rgba(127, 127, 127, 0.08);
  border: 1px solid rgba(127, 127, 127, 0.15);
}

.claims-table-wrapper {
  overflow-x: auto;
  border-radius: 4px;
}
</style>

