/**
 * GIGANG SecOps - Security Correlation & Zero Trust Console
 * Adapted & enhanced with calm-salk UI aesthetics and micro-interactions
 */

// Fallback Incidents Data
const FALLBACK_INCIDENTS = [
  {
    "incident_id": "INC-20260831-003",
    "title": "공공 Wi-Fi(Rogue AP) 중간자 감청 감지 및 제로 트러스트 자동 차단",
    "severity": "CRITICAL",
    "status": "OPEN",
    "created_at": "2026-08-31 10:30:00",
    "target_user": "minji.kim@company.com",
    "primary_src_ip": "172.20.10.4 (Starbucks_Guest_Free)",
    "correlation_score": 11.5,
    "reasons": [
      { "criteria": "비정상 DNS 응답 변조 감지", "score": 4.0, "description": "인증 서버(auth.corp.com) 질의 시 비공식 사설 IP(192.168.1.99)로 응답 반환" },
      { "criteria": "SSL 인증서 위조/Stripping 시도", "score": 4.0, "description": "신뢰할 수 없는 사설 CA(Untrusted Self-Signed Certificate) 감청 프록시 포착" },
      { "criteria": "네트워크 RTT 이상 급증", "score": 2.0, "description": "게이트웨이 응답 지연 시간이 평소(15ms) 대비 180ms로 비정상 증가" },
      { "criteria": "제로 트러스트 PDP 정책 위반", "score": 1.5, "description": "미인증 오픈 Wi-Fi 환경에서 사내 핵심 금융/결제 API 직접 접근 시도" }
    ],
    "attack_timeline": [
      {
        "step": 1,
        "timestamp": "2026-08-31 10:28:10",
        "source": "endpoint",
        "stage": "Untrusted AP Association",
        "description": "사용자 단말이 외부 공공 Wi-Fi (SSID: 'Starbucks_Guest_Free')에 자동 연결됨",
        "raw_log_id": "LOG-WIFI-0102"
      },
      {
        "step": 2,
        "timestamp": "2026-08-31 10:28:45",
        "source": "endpoint",
        "stage": "DNS Spoofing Detected",
        "description": "DNS 캐시 포이즈닝으로 auth.corp.com 요청이 공격자 프록시(192.168.1.99)로 우회됨",
        "raw_log_id": "LOG-DNS-4091"
      },
      {
        "step": 3,
        "timestamp": "2026-08-31 10:29:15",
        "source": "endpoint",
        "stage": "MitM SSL Interception",
        "description": "공격자 프록시가 가짜 SSL 인증서를 주입하여 HTTPS 평문 패킷 감청 시도",
        "raw_log_id": "LOG-SSL-8812"
      },
      {
        "step": 4,
        "timestamp": "2026-08-31 10:29:40",
        "source": "server",
        "stage": "Zero Trust PDP Block",
        "description": "사내 API 게이트웨이가 클라이언트 위험 점수 95점 판정 후 금융 API 접근 즉시 거부",
        "raw_log_id": "LOG-GW-9011"
      }
    ],
    "network_path": [
      { "from_node": "📱 모바일 단말 (172.20.10.4)", "to_node": "⚠️ 가짜 AP / 프록시 (192.168.1.99)", "port": 80, "protocol": "HTTP/MitM", "status": "INTERCEPTED" },
      { "from_node": "⚠️ 가짜 AP (192.168.1.99)", "to_node": "🛡️ 사내 API GW (10.0.0.5)", "port": 443, "protocol": "HTTPS", "status": "BLOCKED" }
    ],
    "ai_analysis": {
      "summary": "사용자가 카페 오픈 Wi-Fi 환경에 접속한 상태에서 악의적인 중간자 공격자(Rogue AP)에 의해 DNS 변조 및 SSL 가짜 인증서 주입이 탐지되었습니다. 제로 트러스트 PDP 정책에 따라 중요 금융 API 접근이 즉시 차단되었으며, 안전한 사내 VPN 터널링으로 강제 전환이 요구됩니다.",
      "mitre_tactics": [
        "T1557.002 (MitM: DNS Spoofing)",
        "T1556 (Auth Modification)",
        "T1040 (Network Sniffing)"
      ],
      "confidence": 0.98,
      "recommended_playbook": [
        {
          "action": "단말 암호화 VPN 터널링 강제 전환",
          "command": "mobile-agent-cli --enforce-vpn --profile corp-secure-vpn --strict",
          "target": "Mobile Client Agent",
          "status": "PENDING"
        },
        {
          "action": "노출 위험 임시 세션 토큰 즉시 무효화",
          "command": "redis-cli DEL session:token:minji.kim@company.com",
          "target": "Auth Redis Cluster",
          "status": "PENDING"
        },
        {
          "action": "사용자 모바일 푸시 보안 경고 발송",
          "command": "push-notify --user minji.kim '⚠️ 안전하지 않은 Wi-Fi 감지: 사내 VPN으로 자동 전환되었습니다.'",
          "target": "Push Notification Service",
          "status": "PENDING"
        }
      ]
    }
  },
  {
    "incident_id": "INC-20260831-001",
    "title": "다단계 횡적이동 및 DB 대량 유출 의심 침해사고",
    "severity": "HIGH",
    "status": "OPEN",
    "created_at": "2026-08-31 10:15:30",
    "target_user": "admin",
    "primary_src_ip": "203.0.113.10",
    "correlation_score": 12.0,
    "reasons": [
      { "criteria": "동일 사용자 계정", "score": 2.0, "description": "인증, 점프서버, DB 접속 계정이 'admin'으로 일치함" },
      { "criteria": "IP 연결 및 네트워크 홉 체인", "score": 4.0, "description": "203.0.113.10 -> 10.0.0.10(Web) -> 10.0.0.20(Internal) -> 10.0.0.30(DB) 경로 연속성 확인" },
      { "criteria": "시간적 인접성 (Time Window)", "score": 2.0, "description": "전체 공격 행위가 8분 20초 이내에 연속 발생" },
      { "criteria": "공격 행동 순서 일치 (Kill Chain)", "score": 4.0, "description": "무차별 대입 -> 인증 성공 -> 내부 침투 -> DB 접근 -> 외부 비정상 송신 순서 부합" }
    ],
    "attack_timeline": [
      {
        "step": 1,
        "timestamp": "2026-08-31 10:01:05",
        "source": "auth",
        "stage": "Initial Access Attempt",
        "description": "외부 IP(203.0.113.10)에서 SSH admin 계정 로그인 실패 12회 연속 발생",
        "raw_log_id": "LOG-AUTH-0891"
      },
      {
        "step": 2,
        "timestamp": "2026-08-31 10:02:10",
        "source": "auth",
        "stage": "Initial Access Success",
        "description": "외부 IP(203.0.113.10)에서 SSH admin 로그인 성공 (웹서버 10.0.0.10)",
        "raw_log_id": "LOG-AUTH-0902"
      },
      {
        "step": 3,
        "timestamp": "2026-08-31 10:04:22",
        "source": "firewall",
        "stage": "Lateral Movement",
        "description": "Web(10.0.0.10) -> Internal Jump Server(10.0.0.20) 포트 22 허용 통신",
        "raw_log_id": "LOG-FW-3401"
      },
      {
        "step": 4,
        "timestamp": "2026-08-31 10:06:45",
        "source": "server",
        "stage": "Internal Pivot",
        "description": "Internal Server(10.0.0.20)에서 DB Client 툴 실행 및 관리자 권한 상승",
        "raw_log_id": "LOG-SRV-1120"
      },
      {
        "step": 5,
        "timestamp": "2026-08-31 10:07:30",
        "source": "db",
        "stage": "Data Access",
        "description": "DB Server(10.0.0.30) 포트 3306 접근 및 customers_pii 테이블 50,000건 SELECT 쿼리 실행",
        "raw_log_id": "LOG-DB-7811"
      },
      {
        "step": 6,
        "timestamp": "2026-08-31 10:09:25",
        "source": "firewall",
        "stage": "Exfiltration Attempt",
        "description": "Internal(10.0.0.20) -> 외부 비인가 IP(198.51.100.77:8080)로 125MB 대용량 이상 송신 감지",
        "raw_log_id": "LOG-FW-3599"
      }
    ],
    "network_path": [
      { "from_node": "Attacker (203.0.113.10)", "to_node": "Web Server (10.0.0.10)", "port": 22, "protocol": "SSH", "status": "COMPROMISED" },
      { "from_node": "Web Server (10.0.0.10)", "to_node": "Internal Jump (10.0.0.20)", "port": 22, "protocol": "SSH", "status": "LATERAL_MOVE" },
      { "from_node": "Internal Jump (10.0.0.20)", "to_node": "DB Server (10.0.0.30)", "port": 3306, "protocol": "MySQL", "status": "DATA_ACCESS" },
      { "from_node": "Internal Jump (10.0.0.20)", "to_node": "Exfil Target (198.51.100.77)", "port": 8080, "protocol": "TCP", "status": "EXFILTRATION" }
    ],
    "ai_analysis": {
      "summary": "공격자 IP(203.0.113.10)가 admin 계정 무차별 대입 공격 성공 후 웹서버를 거점으로 내부 점프서버로 횡적이동을 수행했습니다. 최종적으로 3306 포트를 통해 고객 개인정보 테이블을 조회하고 외부 C2로 데이터 전송을 시도한 고위험 다단계 침해사고입니다.",
      "mitre_tactics": [
        "T1110 (Brute Force)",
        "T1078 (Valid Accounts)",
        "T1021.004 (SSH Pivot)",
        "T1005 (Data Access)",
        "T1041 (Exfiltration)"
      ],
      "confidence": 0.96,
      "recommended_playbook": [
        {
          "action": "공격자 및 유출지 IP 방화벽 차단",
          "command": "iptables -A INPUT -s 203.0.113.10 -j DROP && iptables -A OUTPUT -d 198.51.100.77 -j DROP",
          "target": "Firewall / Gateway",
          "status": "PENDING"
        },
        {
          "action": "침해 계정 'admin' 세션 강제 종료 및 임시 잠금",
          "command": "pkill -u admin && usermod -L admin",
          "target": "Web & Internal Server",
          "status": "PENDING"
        },
        {
          "action": "DB 활성 악성 연결 즉시 종료",
          "command": "mysqladmin -u root processlist | grep admin | awk '{print $1}' | xargs -I {} mysqladmin kill {}",
          "target": "DB Server (10.0.0.30)",
          "status": "PENDING"
        }
      ]
    }
  },
  {
    "incident_id": "INC-20260831-002",
    "title": "단일 웹 엔드포인트 비정상 SQL 인젝션 시도",
    "severity": "MEDIUM",
    "status": "CONTAINED",
    "created_at": "2026-08-31 09:40:10",
    "target_user": "anonymous",
    "primary_src_ip": "198.51.100.44",
    "correlation_score": 6.0,
    "reasons": [
      { "criteria": "동일 출발지 IP", "score": 2.0, "description": "198.51.100.44에서 연속 웹 취약점 스캔 요청" },
      { "criteria": "행동 순서 일치", "score": 4.0, "description": "URI 파라미터 내 UNION SELECT 삽입 후 WAF 차단 기록 확인" }
    ],
    "attack_timeline": [
      {
        "step": 1,
        "timestamp": "2026-08-31 09:38:00",
        "source": "server",
        "stage": "Reconnaissance",
        "description": "공격자 IP(198.51.100.44)에서 웹 엔드포인트 /api/products?id=1' OR '1'='1 스캔 시도",
        "raw_log_id": "LOG-SRV-0980"
      },
      {
        "step": 2,
        "timestamp": "2026-08-31 09:39:15",
        "source": "firewall",
        "stage": "WAF Block",
        "description": "WAF에서 공격 IP 차단 룰 발동 (403 Forbidden 응답)",
        "raw_log_id": "LOG-FW-3200"
      }
    ],
    "network_path": [
      { "from_node": "Attacker (198.51.100.44)", "to_node": "WAF / Gateway (10.0.0.5)", "port": 443, "protocol": "HTTPS", "status": "BLOCKED" }
    ],
    "ai_analysis": {
      "summary": "단일 외부 IP에서 발생한 자동화된 SQL 인젝션 스캔 시도입니다. WAF에 의해 즉시 차단되어 내부 시스템 침투에는 실패했습니다.",
      "mitre_tactics": ["T1190 (Exploit Public-Facing Application)"],
      "confidence": 0.88,
      "recommended_playbook": [
        {
          "action": "공격자 IP 24시간 임시 밴 목록 추가",
          "command": "fail2ban-client set nginx-sqli banip 198.51.100.44",
          "target": "WAF Gateway",
          "status": "EXECUTED"
        }
      ]
    }
  }
];

const $ = id => document.getElementById(id);
const rnd = (a, b) => Math.floor(Math.random() * (b - a + 1)) + a;
const pick = a => a[rnd(0, a.length - 1)];
const pad = n => String(n).padStart(2, '0');

let incidents = [];
let currentIncident = null;
let currentView = 'overview';

// ==================== INITIALIZATION ====================
document.addEventListener("DOMContentLoaded", async () => {
  initClock();
  initTrafficChart();
  initSecurityGauge();
  initLiveFeed();
  await fetchIncidents();
  renderIncidentSelector();
  selectIncident(0);
});

// ==================== CLOCK ====================
function initClock() {
  const update = () => {
    const now = new Date();
    $('clock').textContent = now.toLocaleString('ko-KR', {
      year: 'numeric', month: 'long', day: 'numeric',
      weekday: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit'
    }) + ' · 실시간 관제 중';
  };
  setInterval(update, 1000);
  update();
}

// ==================== INCIDENT DATA & SELECTION ====================
async function fetchIncidents() {
  try {
    const res = await fetch("/api/incidents");
    if (res.ok) {
      incidents = await res.json();
    } else {
      incidents = FALLBACK_INCIDENTS;
    }
  } catch (e) {
    console.log("Backend offline, using fallback incidents:", e);
    incidents = FALLBACK_INCIDENTS;
  }
}

function renderIncidentSelector() {
  const sel = $('incidentSelect');
  sel.innerHTML = "";
  incidents.forEach((inc, idx) => {
    const opt = document.createElement("option");
    opt.value = idx;
    opt.textContent = `[${inc.severity}] ${inc.incident_id} - ${inc.title.substring(0, 24)}...`;
    sel.appendChild(opt);
  });
}

function selectIncident(index) {
  currentIncident = incidents[index];
  if (!currentIncident) return;

  // Top KPIs
  const sevEl = $('kpiSeverity');
  sevEl.textContent = currentIncident.severity;
  if (currentIncident.severity === "CRITICAL") {
    sevEl.style.color = "var(--red)";
  } else if (currentIncident.severity === "HIGH") {
    sevEl.style.color = "var(--amber)";
  } else {
    sevEl.style.color = "var(--cyan)";
  }

  $('kpiScore').innerHTML = `${currentIncident.correlation_score} <span style="font-size:16px;font-weight:400;color:var(--muted)">/ 12.0</span>`;
  
  const statusEl = $('kpiStatus');
  statusEl.textContent = currentIncident.status;
  statusEl.style.color = currentIncident.status === "OPEN" ? "var(--amber)" : "var(--green)";

  // Incident Banner
  $('incidentTitle').textContent = currentIncident.title;
  $('incidentId').textContent = currentIncident.incident_id;
  $('incidentTime').textContent = currentIncident.created_at;
  $('incidentUser').textContent = currentIncident.target_user || '미상';
  $('incidentIp').textContent = currentIncident.primary_src_ip || '127.0.0.1';

  const tag = $('incidentTag');
  tag.textContent = `${currentIncident.severity} INCIDENT`;
  tag.className = `tag ${currentIncident.severity === 'CRITICAL' ? 'crit' : currentIncident.severity === 'HIGH' ? 'high' : 'med'}`;

  // Copilot default reference
  if ($('chatIncidentTitle')) {
    $('chatIncidentTitle').textContent = currentIncident.title;
  }

  // Render Sub-Components
  renderBriefing();
  renderTimeline();
  renderNetworkMap();
}

function onIncidentChange() {
  const idx = $('incidentSelect').value;
  selectIncident(idx);
}

// ==================== VIEW SWITCHING ====================
function switchView(viewName) {
  currentView = viewName;
  const views = ['overview', 'briefing', 'timeline', 'network', 'copilot', 'logs'];

  views.forEach(v => {
    const vEl = $('view-' + v);
    if (vEl) vEl.style.display = (v === viewName) ? 'block' : 'none';

    const tabBtn = $('tab-' + v);
    if (tabBtn) tabBtn.classList.toggle('active', v === viewName);

    const navLink = $('nav-' + v);
    if (navLink) navLink.classList.toggle('on', v === viewName);
  });

  // Trigger chart re-draw if overview became visible
  if (viewName === 'overview') {
    setTimeout(fitChart, 50);
  }
}

// ==================== TAB 2: AI BRIEFING & SOAR ====================
function renderBriefing() {
  const ai = currentIncident.ai_analysis || {};
  $('aiSummaryText').textContent = ai.summary || "분석 요약 정보가 없습니다.";

  // MITRE Tactics
  const mitreBox = $('mitreContainer');
  mitreBox.innerHTML = "";
  (ai.mitre_tactics || []).forEach(t => {
    const span = document.createElement("span");
    span.className = "mitre-tag";
    span.textContent = `🎯 ${t}`;
    mitreBox.appendChild(span);
  });

  // SOAR Playbook
  const pbBox = $('playbookContainer');
  pbBox.innerHTML = "";
  (ai.recommended_playbook || []).forEach((item, idx) => {
    const isDone = item.status === "EXECUTED";
    const card = document.createElement("div");
    card.className = "playbook-card";
    card.innerHTML = `
      <div class="playbook-info">
        <div class="playbook-title">
          <span>${idx + 1}. ${item.action}</span>
          <span class="tag med">${item.target}</span>
        </div>
        <code class="playbook-cmd">${item.command}</code>
      </div>
      <button class="btn-soar ${isDone ? 'done' : 'pending'}" 
              onclick="executeSoarAction(${idx}, '${item.command.replace(/'/g, "\\'")}', this)" 
              ${isDone ? 'disabled' : ''}>
        ${isDone ? '✅ 조치 완료' : '🚀 1-Click 실행'}
      </button>
    `;
    pbBox.appendChild(card);
  });
}

async function executeSoarAction(idx, command, btn) {
  btn.disabled = true;
  btn.textContent = "⏳ 실행 중...";

  try {
    await fetch("/api/soar/execute", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        incident_id: currentIncident.incident_id,
        action_index: idx,
        command: command
      })
    });
  } catch (e) {
    console.log("Local SOAR simulation executed:", e);
  }

  btn.className = "btn-soar done";
  btn.textContent = "✅ 조치 완료";
  showToast(`[SOAR 자동 대응 완료] ${command}`);
  addFeed(`[SOAR] 명령 실행됨: ${command}`, 'var(--green)');
}

// ==================== TAB 3: TIMELINE & CRITERIA ====================
function renderTimeline() {
  // Criteria Score Cards
  const rBox = $('reasonsContainer');
  rBox.innerHTML = "";
  (currentIncident.reasons || []).forEach(r => {
    const div = document.createElement("div");
    div.className = "score-card";
    div.innerHTML = `
      <div class="val">+${r.score.toFixed(1)}점</div>
      <div class="title">${r.criteria}</div>
      <div class="desc">${r.description}</div>
    `;
    rBox.appendChild(div);
  });

  // Timeline Step Cards
  const tBox = $('timelineContainer');
  tBox.innerHTML = "";
  (currentIncident.attack_timeline || []).forEach(step => {
    const card = document.createElement("div");
    card.className = "step-card";
    card.innerHTML = `
      <div class="step-main">
        <span class="step-badge">STEP ${step.step}</span>
        <div class="step-content">
          <div class="stage">[${step.source.toUpperCase()}] ${step.stage}</div>
          <div class="desc">${step.description}</div>
          <div class="log-id">Raw Log ID: ${step.raw_log_id}</div>
        </div>
      </div>
      <div class="step-time">${step.timestamp}</div>
    `;
    tBox.appendChild(card);
  });
}

// ==================== TAB 4: NETWORK MAP ====================
function renderNetworkMap() {
  const hops = currentIncident.network_path || [];
  const container = $('networkHopsContainer');
  container.innerHTML = "";

  hops.forEach((hop, idx) => {
    const node = document.createElement("div");
    node.className = "hop-node";
    node.innerHTML = `<div class="node-title">${hop.from_node}</div>`;
    container.appendChild(node);

    const arrow = document.createElement("div");
    arrow.className = "hop-arrow";
    arrow.innerHTML = `➔ :${hop.port}<small>${hop.protocol} (${hop.status})</small>`;
    container.appendChild(arrow);

    if (idx === hops.length - 1) {
      const endNode = document.createElement("div");
      endNode.className = "hop-node";
      endNode.innerHTML = `<div class="node-title">${hop.to_node}</div>`;
      container.appendChild(endNode);
    }
  });
}

// ==================== TAB 5: AI COPILOT ====================
async function sendCopilotQuestion() {
  const input = $('copilotInput');
  const q = input.value.trim();
  if (!q) return;

  appendChatMsg("user", q);
  input.value = "";

  const loadId = appendChatMsg("assistant", "🤖 AI 분석관이 상관분석 사건 데이터를 정밀 검토 중입니다...");

  try {
    const res = await fetch("/api/ai/copilot", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        incident_id: currentIncident.incident_id,
        question: q
      })
    });
    if (res.ok) {
      const data = await res.json();
      updateChatMsg(loadId, data.answer);
      return;
    }
  } catch (e) {
    console.log("Copilot using local fallback:", e);
  }

  // Smart Fallback
  let ans = "";
  const query = q.toLowerCase();
  if (query.includes("가짜 ap") || query.includes("wifi") || query.includes("원인")) {
    ans = "공식 도메인(auth.corp.com)에 대해 비정상 사설 IP(192.168.1.99)로 DNS가 위조 응답되었고, 신뢰할 수 없는 사설 CA 인증서가 감청 프록시를 통해 주입되어 중간자(MitM) 감청 공격으로 판정되었습니다.";
  } else if (query.includes("알림") || query.includes("문구")) {
    ans = "📱 <b>[사용자 발송 보안 알림 문구]</b><br>⚠️ <i>'보안 경고: 현재 연결된 Wi-Fi(Starbucks_Guest_Free)는 비인가 가짜 AP(Rogue AP)로 의심됩니다. 정보 보호를 위해 사내 보안 VPN으로 자동 전환되었습니다.'</i>";
  } else if (query.includes("vpn") || query.includes("스크립트") || query.includes("명령어")) {
    ans = "🔒 <b>[단말 격리 및 세션 종료 스크립트]</b><br><pre class='mono' style='background:rgba(0,0,0,0.4);padding:8px;border-radius:6px;'>mobile-agent-cli --enforce-vpn --profile corp-secure-vpn\nredis-cli DEL session:token:minji.kim@company.com</pre>";
  } else if (query.includes("db") || query.includes("유출")) {
    ans = "DB 서버(10.0.0.30:3306)에서 <code>customers_pii</code> 테이블 대상 50,000건의 비정상 대량 SELECT 쿼리가 발생한 후 외부 IP(198.51.100.77)로 대량 송신이 포착되었습니다.";
  } else {
    ans = `분석 결과, 현재 사건은 <b>${currentIncident.title}</b>(위험도: ${currentIncident.severity})입니다. 권장 초동 조치로 '1-Click SOAR 대응' 탭에서 방화벽 차단 또는 VPN 강제 전환을 즉시 수행하시기 바랍니다.`;
  }
  updateChatMsg(loadId, ans);
}

function askCopilotPreset(text) {
  $('copilotInput').value = text;
  sendCopilotQuestion();
}

function appendChatMsg(role, text) {
  const box = $('chatHistory');
  const id = "msg_" + Date.now() + Math.random().toString(36).substr(2, 4);
  const div = document.createElement("div");
  div.id = id;
  div.className = `chat-msg ${role}`;
  div.innerHTML = role === "user" ? `👤 <b>분석관:</b> ${text}` : `🤖 <b>AI Copilot:</b> ${text}`;
  box.appendChild(div);
  box.scrollTop = box.scrollHeight;
  return id;
}

function updateChatMsg(id, text) {
  const el = $(id);
  if (el) {
    el.innerHTML = `🤖 <b>AI Copilot:</b> ${text}`;
    const box = $('chatHistory');
    box.scrollTop = box.scrollHeight;
  }
}

// ==================== ATTACK SIMULATION ====================
async function triggerSimulation() {
  showToast("⚡ 모의 침해 공격 로그 스트림 발생을 시작합니다...");
  addFeed("모의 공격 시뮬레이션 트리거됨: Rogue AP 감청 및 DNS 변조 시도", "var(--red)");
  
  try {
    await fetch("/api/logs/simulate", { method: "POST" });
  } catch (e) {
    console.log("Simulation offline trigger:", e);
  }

  setTimeout(() => {
    for (let i = 0; i < 3; i++) addEvent();
    showToast("새로운 보안 이상 징후가 수집되어 상관분석 중입니다.");
  }, 1000);
}

// ==================== REAL-TIME TRAFFIC CANVAS (calm-salk) ====================
let cv, cx;
const N = 60;
const good = Array.from({ length: N }, () => rnd(45, 75));
const bad = Array.from({ length: N }, () => rnd(3, 14));

function initTrafficChart() {
  cv = $('chart');
  cx = cv.getContext('2d');
  window.addEventListener('resize', () => { fitChart(); drawChart(); });
  fitChart();
  drawChart();

  setInterval(() => {
    good.push(Math.max(25, Math.min(90, good.at(-1) + rnd(-7, 7))));
    good.shift();
    bad.push(Math.max(1, Math.min(38, bad.at(-1) + rnd(-4, 4))));
    bad.shift();
    drawChart();
  }, 1000);
}

function fitChart() {
  if (!cv) return;
  const r = cv.getBoundingClientRect();
  const d = window.devicePixelRatio || 1;
  cv.width = r.width * d;
  cv.height = r.height * d;
  cx.setTransform(d, 0, 0, d, 0, 0);
}

function drawLine(data, color, w, h, fill) {
  cx.beginPath();
  data.forEach((v, i) => {
    const x = i / (N - 1) * w;
    const y = h - (v / 100) * h;
    i ? cx.lineTo(x, y) : cx.moveTo(x, y);
  });
  cx.strokeStyle = color;
  cx.lineWidth = 2.2;
  cx.lineJoin = 'round';
  cx.stroke();

  if (fill) {
    cx.lineTo(w, h);
    cx.lineTo(0, h);
    cx.closePath();
    const g = cx.createLinearGradient(0, 0, 0, h);
    g.addColorStop(0, fill);
    g.addColorStop(1, 'transparent');
    cx.fillStyle = g;
    cx.fill();
  }
}

function drawChart() {
  if (!cv) return;
  const r = cv.getBoundingClientRect();
  const w = r.width, h = r.height;
  cx.clearRect(0, 0, w, h);

  // Background grid
  cx.strokeStyle = 'rgba(120, 150, 210, 0.1)';
  cx.lineWidth = 1;
  for (let i = 1; i < 5; i++) {
    cx.beginPath();
    cx.moveTo(0, h * i / 5);
    cx.lineTo(w, h * i / 5);
    cx.stroke();
  }

  drawLine(good, '#22d3ee', w, h, 'rgba(34, 211, 238, 0.22)');
  drawLine(bad, '#f43f5e', w, h, 'rgba(244, 63, 94, 0.25)');
}

// ==================== SECURITY SCORE GAUGE (calm-salk) ====================
function initSecurityGauge() {
  const c = $('gauge').getContext('2d');
  const s = 360, m = s / 2, r = 150;
  c.lineWidth = 22;
  c.lineCap = 'round';

  // Background arc
  c.strokeStyle = 'rgba(255, 255, 255, 0.07)';
  c.beginPath();
  c.arc(m, m, r, 0.75 * Math.PI, 2.25 * Math.PI);
  c.stroke();

  // Gradient arc
  const g = c.createLinearGradient(0, 0, s, s);
  g.addColorStop(0, '#22d3ee');
  g.addColorStop(1, '#8b5cf6');
  c.strokeStyle = g;
  c.beginPath();
  c.arc(m, m, r, 0.75 * Math.PI, (0.75 + 1.5 * 0.92) * Math.PI);
  c.stroke();
}

// ==================== LIVE EVENTS & NOTIFICATION FEED ====================
const kinds = [
  ['Rogue AP 중간자 감청', 'crit', 80],
  ['DNS 캐시 포이즈닝', 'crit', 53],
  ['SSH 무차별 대입', 'high', 22],
  ['내부 점프서버 횡적이동', 'crit', 22],
  ['DB 대량 SELECT 쿼리', 'high', 3306],
  ['비인가 C2 외부 송신', 'crit', 8080],
  ['WAF SQL 인젝션', 'med', 443],
  ['신뢰할 수 없는 CA 주입', 'high', 443]
];
const label = { crit: '치명', high: '높음', med: '보통' };
const acts = [['차단', 'ok'], ['격리', 'ok'], ['VPN 강제', 'ok'], ['모니터링', 'med']];
const ip = () => `${pick([172, 192, 203, 198, 103, 45])}.${rnd(1, 254)}.${rnd(1, 254)}.${rnd(1, 254)}`;

function addEvent() {
  const [name, sev, port] = pick(kinds);
  const [act, ac] = pick(acts);
  const d = new Date();
  const timeStr = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  const ipStr = ip();

  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td class="mono">${timeStr}</td>
    <td>${name}</td>
    <td class="mono">${ipStr}</td>
    <td class="mono">${port}</td>
    <td><span class="tag ${sev}">${label[sev]}</span></td>
    <td><span class="tag ${ac}">${act}</span></td>
  `;

  // Prepend to top table
  const tb = $('events');
  if (tb) {
    tb.prepend(tr);
    while (tb.children.length > 7) tb.lastChild.remove();
  }

  // Prepend to full log table if present
  const fullTb = $('fullLogTable');
  if (fullTb) {
    const tr2 = tr.cloneNode(true);
    fullTb.prepend(tr2);
    while (fullTb.children.length > 20) fullTb.lastChild.remove();
  }

  if (sev === 'crit') {
    addFeed(`${name} 탐지 (${ipStr}) — 자동 방어 정책 적용`, 'var(--red)');
  }
}

function addFeed(msg, color) {
  const d = new Date();
  const e = document.createElement('div');
  e.className = 'ev';
  e.innerHTML = `
    <span class="pin" style="background:${color};box-shadow:0 0 8px ${color}"></span>
    <div>${msg}<small>${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}</small></div>
  `;
  const feed = $('feed');
  if (feed) {
    feed.prepend(e);
    while (feed.children.length > 7) feed.lastChild.remove();
  }
}

function initLiveFeed() {
  // Threat Types
  const types = [
    ['Rogue AP / Wi-Fi MitM', 35],
    ['SSH 무차별 대입 & 횡적이동', 28],
    ['DB 이상 대량 접근', 18],
    ['SQL Injection 스캔', 12],
    ['악성코드 C2 통신', 7]
  ];
  $('types').innerHTML = types.map(([n, v]) => `
    <div class="bar">
      <div><span>${n}</span><span>${v}%</span></div>
      <div class="t"><i style="width:${v * 2.2}%"></i></div>
    </div>
  `).join('');

  addFeed('GIGANG 상관분석 엔진 v3.8 가동 시작', 'var(--green)');
  addFeed('제로 트러스트 PDP 정책 v2026.10.07 동기화 완료', 'var(--cyan)');
  addFeed('센서 및 로그 에이전트 24/24 정상 연결', 'var(--green)');

  for (let i = 0; i < 5; i++) addEvent();
  (function loop() {
    addEvent();
    setTimeout(loop, rnd(2000, 4500));
  })();
}

// Live KPI Increment
let blockedCount = 184392;
setInterval(() => {
  blockedCount += rnd(1, 4);
  const k1 = $('k1');
  if (k1) k1.textContent = blockedCount.toLocaleString();
}, 2500);

// ==================== TOAST NOTIFICATION ====================
let toastTimer = null;
function showToast(msg) {
  const t = $('toast');
  if (!t) return;
  t.textContent = msg;
  t.classList.add('show');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    t.classList.remove('show');
  }, 3500);
}
