/**
 * KKuTu-Lite Main Game & Real-Time Multiplayer Engine
 * - Supports:
 *   1) Local Server SSE/HTTP sync (when opened via kkutu-server.exe / http://)
 *   2) Multi-Tab BroadcastChannel + localStorage sync (works even on file://)
 *   3) Internet Friends P2P WebRTC (PeerJS invite code)
 *   4) Built-in KKuTu AI Bot players with realistic live typing preview
 */

const App = (() => {
  const AVATARS = ['🦊', '🐼', '🐯', '🐰', '🐸', '🐱', '🐶', '🐧', '🐥', '🦄', '🐲', '🐹'];

  // 내 프로필 상태
  let myUser = {
    id: 'u_' + Math.random().toString(36).slice(2, 9),
    nickname: '끄투러' + Math.floor(100 + Math.random() * 900),
    avatar: AVATARS[Math.floor(Math.random() * AVATARS.length)],
    totalScore: 0,
    wins: 0,
    roomId: null,
    isSpectator: false
  };

  // 전체 상태 (유저 맵, 방 맵)
  const usersMap = new Map(); // userId -> userObj
  const roomsMap = new Map(); // roomId -> roomObj
  let currentRoomFilter = 'ALL';
  let forceChatMode = false; // 내 턴일 때도 강제로 채팅 모드로 전송할지 여부
  let editingRoomMode = false; // 방 만들기 모달이 '방 설정 변경'인지 여부

  // 게임 진행 타이머 핸들
  let hostGameInterval = null;
  let botActionTimeout = null;
  let lastTickSecond = -1;
  let lastTurnFocusKey = '';
  let wordRejectRevertTimeout = null;

  // 네트워크 핸들
  let bcChannel = null;
  let sseSource = null;
  let serverAvailable = false;
  let peerInstance = null;
  let peerConnections = new Map(); // peerId -> DataConnection
  let myInviteCode = null;
  let targetRoomToAutoJoin = null;

  // ==========================================
  // 1. 초기화 및 프로필 로드
  // ==========================================
  function init() {
    loadProfile();
    usersMap.set(myUser.id, { ...myUser, lastSeen: Date.now() });

    initNetwork();
    bindUIEvents();
    renderProfileHeader();
    renderLobbyUsers();
    renderRoomsList();
    updateDictStatsUI();
    startClientSmoothTimerLoop();

    addLobbySystemChat('🎉 끄투 LITE에 오신 것을 환영합니다! (표준국어대사전 33만 단어 탑재)');

    // URL 파라미터 1-클릭 초대 링크 (?host=...&room=...) 자동 연결
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const autoHost = urlParams.get('host');
      const autoRoom = urlParams.get('room');
      if (autoHost) {
        addLobbySystemChat(`🌐 초대 링크 감지: 호스트(${autoHost})와 연결을 시작합니다...`);
        setTimeout(() => {
          connectToRemotePeer(autoHost, autoRoom);
        }, 600);
      }
    } catch (e) {}

    // 주기적 하트비트 (접속자 및 방 상태 동기화)
    setInterval(() => {
      myUser.lastSeen = Date.now();
      usersMap.set(myUser.id, { ...myUser });
      broadcastPacket({
        type: 'HEARTBEAT',
        user: myUser,
        hostedRoom: getMyHostedRoomSnapshot()
      });
      pruneStaleUsers();
    }, 2500);

    // 입장 직후 전체 상태 요청
    setTimeout(() => {
      broadcastPacket({
        type: 'HELLO_SYNC_REQ',
        user: myUser,
        customWords: DictionaryEngine.getCustomWordsList()
      });
    }, 250);
  }

  function loadProfile() {
    try {
      const savedTheme = localStorage.getItem('kkutu_theme_v1');
      if (savedTheme) {
        document.documentElement.setAttribute('data-theme', savedTheme);
        const sel = document.getElementById('themeSelect');
        if (sel) sel.value = savedTheme;
      }
      const saved = localStorage.getItem('kkutu_my_profile_v1');
      if (saved) {
        const parsed = JSON.parse(saved);
        if (parsed.nickname) myUser.nickname = parsed.nickname;
        if (parsed.avatar) myUser.avatar = parsed.avatar;
        if (typeof parsed.totalScore === 'number') myUser.totalScore = parsed.totalScore;
        if (typeof parsed.wins === 'number') myUser.wins = parsed.wins;
      }
    } catch (e) {}
  }

  function applyTheme(themeName) {
    document.documentElement.setAttribute('data-theme', themeName);
    try {
      localStorage.setItem('kkutu_theme_v1', themeName);
    } catch (e) {}
  }

  function saveProfile() {
    try {
      localStorage.setItem('kkutu_my_profile_v1', JSON.stringify({
        nickname: myUser.nickname,
        avatar: myUser.avatar,
        totalScore: myUser.totalScore,
        wins: myUser.wins
      }));
    } catch (e) {}
  }

  // ==========================================
  // 2. 멀티플레이어 네트워크 계층 (3중 하이브리드)
  // ==========================================
  function initNetwork() {
    // 1) BroadcastChannel (동일 PC 멀티탭 실시간 연동)
    if (typeof BroadcastChannel !== 'undefined') {
      bcChannel = new BroadcastChannel('kkutu_channel_v1');
      bcChannel.onmessage = (ev) => {
        if (ev && ev.data) handleIncomingPacket(ev.data, false);
      };
    }

    // localStorage fallback 이벤트
    window.addEventListener('storage', (ev) => {
      if (ev.key === 'kkutu_net_packet_v1' && ev.newValue) {
        try {
          const pkt = JSON.parse(ev.newValue);
          handleIncomingPacket(pkt, false);
        } catch (e) {}
      }
    });

    // 2) 로컬 환경(localhost)에서만 C# SSE 서버 연결 시도 (Vercel 배포 시 불필요한 404 방지)
    const isLocalhost = location.hostname === 'localhost' || location.hostname === '127.0.0.1';
    if (isLocalhost && location.protocol.startsWith('http')) {
      tryConnectLocalServer();
    } else {
      updateNetStatusPill('Vercel P2P 온라인');
    }

    // 3) Vercel 환경에서는 페이지 로드 즉시 P2P WebRTC 호스트 준비
    setTimeout(() => {
      initPeerJSHost();
    }, 350);

    // 페이지 닫을 때 퇴장 알림
    window.addEventListener('beforeunload', () => {
      if (myUser.roomId) {
        leaveCurrentRoom(true);
      }
      broadcastPacket({ type: 'USER_LEAVE', userId: myUser.id });
    });
  }

  function tryConnectLocalServer() {
    try {
      sseSource = new EventSource('/api/events?clientId=' + encodeURIComponent(myUser.id));
      sseSource.onopen = () => {
        serverAvailable = true;
        updateNetStatusPill('로컬 서버 + 멀티탭 동기화됨');
      };
      sseSource.onmessage = (ev) => {
        if (!ev.data) return;
        try {
          const pkt = JSON.parse(ev.data);
          handleIncomingPacket(pkt, false);
        } catch (e) {}
      };
      sseSource.onerror = () => {
        serverAvailable = false;
      };
    } catch (e) {
      serverAvailable = false;
    }
  }

  // Google 공용 STUN 서버 설정 (서로 다른 공유기/LTE 환경 친구 연결 보장)
  const PEERJS_CONFIG = {
    config: {
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' },
        { urls: 'stun:stun2.l.google.com:19302' },
        { urls: 'stun:global.stun.twilio.com:3478' }
      ]
    }
  };

  // PeerJS (원격 인터넷 친구 초대 코드 연결)
  function initPeerJSHost(callback) {
    if (typeof Peer === 'undefined') {
      return;
    }
    if (peerInstance && myInviteCode) {
      updateInviteModalLinkDisplay(myInviteCode);
      if (callback) callback(myInviteCode);
      return;
    }
    const randomCode = 'KKUTU-' + Math.random().toString(36).slice(2, 8).toUpperCase();
    const peer = new Peer(randomCode, PEERJS_CONFIG);

    peer.on('open', (id) => {
      peerInstance = peer;
      myInviteCode = id;
      updateNetStatusPill(`온라인 (초대 가능: ${id})`);
      updateInviteModalLinkDisplay(id);
      if (callback) callback(id);
    });

    peer.on('connection', (conn) => {
      setupPeerConnection(conn);
    });

    peer.on('error', (err) => {
      if (err.type === 'unavailable-id') {
        peer.destroy();
        peerInstance = null;
        setTimeout(() => initPeerJSHost(callback), 400);
      }
    });
  }

  function updateInviteModalLinkDisplay(code = myInviteCode) {
    const input = document.getElementById('modalInviteLinkInput');
    if (!input) return;
    if (code) {
      const roomPart = myUser.roomId ? `&room=${encodeURIComponent(myUser.roomId)}` : '';
      input.value = `${window.location.origin}${window.location.pathname}?host=${encodeURIComponent(code)}${roomPart}`;
    } else {
      input.value = '초대 코드 생성 중...';
    }
  }

  function connectToRemotePeer(targetInput, autoJoinRoomId = null) {
    if (!targetInput) return;
    let cleanCode = targetInput.trim();

    // 사용자가 전체 URL(예: https://.../?room=101&host=KKUTU-ABC)을 붙여넣었을 경우 자동 파싱!
    if (cleanCode.includes('?')) {
      try {
        const urlObj = new URL(cleanCode.startsWith('http') ? cleanCode : 'https://' + cleanCode);
        const hostParam = urlObj.searchParams.get('host');
        const roomParam = urlObj.searchParams.get('room');
        if (hostParam) cleanCode = hostParam;
        if (roomParam && !autoJoinRoomId) autoJoinRoomId = roomParam;
      } catch (e) {}
    }
    cleanCode = cleanCode.toUpperCase();

    if (autoJoinRoomId) {
      targetRoomToAutoJoin = autoJoinRoomId;
    }

    if (cleanCode === myInviteCode) {
      showToast('⚠️ 자기 자신의 초대 링크/코드입니다.');
      return;
    }

    if (typeof Peer === 'undefined') {
      showToast('PeerJS 라이브러리를 불러오지 못했습니다.');
      return;
    }

    const doConnect = () => {
      const conn = peerInstance.connect(cleanCode, { reliable: true });
      setupPeerConnection(conn, cleanCode);
    };

    if (!peerInstance) {
      const myPeerId = 'KKUTU-USER-' + Math.random().toString(36).slice(2, 8).toUpperCase();
      peerInstance = new Peer(myPeerId, PEERJS_CONFIG);
      peerInstance.on('open', () => {
        doConnect();
      });
      peerInstance.on('connection', (c) => setupPeerConnection(c));
      peerInstance.on('error', (err) => {
        showToast('원격 코드 연결 실패: 링크나 코드를 다시 확인해 주세요 (' + (err.type || '') + ')');
      });
    } else {
      doConnect();
    }
  }

  function setupPeerConnection(conn, labelCode = '') {
    conn.on('open', () => {
      peerConnections.set(conn.peer, conn);
      updateNetStatusPill(`원격 친구 연결됨 (${peerConnections.size}명)`);
      showToast(`🌐 원격 피어(${conn.peer})와 실시간 연결되었습니다!`);

      // 연결 즉시 내 정보, 전체 접속자 목록, 커스텀 단어장, 모든 방 정보 전송
      conn.send({
        senderId: myUser.id,
        type: 'HELLO_SYNC_RES',
        user: myUser,
        users: Array.from(usersMap.values()),
        rooms: Array.from(roomsMap.values()),
        customWords: DictionaryEngine.getCustomWordsList()
      });
    });

    conn.on('data', (data) => {
      if (data && typeof data === 'object') {
        handleIncomingPacket(data, true, conn.peer);
      }
    });

    conn.on('close', () => {
      peerConnections.delete(conn.peer);
      updateNetStatusPill(peerConnections.size > 0 ? `원격 친구 연결됨 (${peerConnections.size}명)` : '멀티탭/로컬 동기화 활성');
    });
  }

  function broadcastPacket(payload, excludePeerId = null) {
    const packet = {
      ...payload,
      senderId: myUser.id,
      _ts: Date.now(),
      _nonce: Math.random().toString(36).slice(2, 7)
    };

    // 1) BroadcastChannel
    if (bcChannel) {
      try { bcChannel.postMessage(packet); } catch (e) {}
    }

    // 2) localStorage event fallback
    try {
      localStorage.setItem('kkutu_net_packet_v1', JSON.stringify(packet));
    } catch (e) {}

    // 3) Local Server POST
    if (serverAvailable) {
      fetch('/api/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(packet)
      }).catch(() => {});
    }

    // 4) WebRTC Peer Connections
    for (const [peerId, conn] of peerConnections.entries()) {
      if (peerId !== excludePeerId && conn.open) {
        try { conn.send(packet); } catch (e) {}
      }
    }
  }

  // 이미 처리한 패킷 중복 방지
  const processedNonces = new Set();

  function handleIncomingPacket(pkt, fromPeer = false, sourcePeerId = null) {
    if (!pkt || pkt.senderId === myUser.id) return;
    if (pkt._nonce) {
      if (processedNonces.has(pkt._nonce)) return;
      processedNonces.add(pkt._nonce);
      if (processedNonces.size > 600) {
        const first = processedNonces.values().next().value;
        processedNonces.delete(first);
      }
    }

    // 내가 WebRTC 호스트일 때 다른 피어들에게 릴레이하고 내 로컬 탭에도 전달
    if (fromPeer && peerConnections.size > 1) {
      for (const [peerId, conn] of peerConnections.entries()) {
        if (peerId !== sourcePeerId && conn.open) {
          try { conn.send(pkt); } catch (e) {}
        }
      }
    }

    switch (pkt.type) {
      case 'HELLO_SYNC_REQ': {
        if (pkt.user) {
          usersMap.set(pkt.user.id, { ...pkt.user, lastSeen: Date.now() });
          renderLobbyUsers();
        }
        if (pkt.customWords) {
          DictionaryEngine.syncRemoteCustomWords(pkt.customWords);
          updateDictStatsUI();
        }
        broadcastPacket({
          type: 'HELLO_SYNC_RES',
          user: myUser,
          users: Array.from(usersMap.values()),
          rooms: Array.from(roomsMap.values()),
          customWords: DictionaryEngine.getCustomWordsList()
        });
        break;
      }

      case 'HELLO_SYNC_RES': {
        if (pkt.user) {
          usersMap.set(pkt.user.id, { ...pkt.user, lastSeen: Date.now() });
        }
        if (Array.isArray(pkt.users)) {
          pkt.users.forEach(u => {
            if (u && u.id) usersMap.set(u.id, { ...u, lastSeen: Date.now() });
          });
        }
        if (pkt.customWords) {
          DictionaryEngine.syncRemoteCustomWords(pkt.customWords);
          updateDictStatsUI();
        }
        if (Array.isArray(pkt.rooms)) {
          pkt.rooms.forEach(r => {
            if (r && r.id) roomsMap.set(r.id, r);
          });
        }
        renderLobbyUsers();
        renderRoomsList();
        if (targetRoomToAutoJoin && roomsMap.has(targetRoomToAutoJoin)) {
          const autoJoinId = targetRoomToAutoJoin;
          targetRoomToAutoJoin = null;
          setTimeout(() => {
            joinRoom(autoJoinId, false);
            showToast(`🎮 초대 링크를 통해 #${autoJoinId} 방에 입장했습니다!`);
          }, 300);
        }
        if (myUser.roomId && roomsMap.has(myUser.roomId)) {
          renderRoomArena();
        }
        break;
      }

      case 'HEARTBEAT': {
        if (pkt.user) {
          usersMap.set(pkt.user.id, { ...pkt.user, lastSeen: Date.now() });
          renderLobbyUsers();
        }
        if (pkt.hostedRoom) {
          const prev = roomsMap.get(pkt.hostedRoom.id);
          const sameActiveTurn = prev &&
            prev.status === 'PLAYING' &&
            pkt.hostedRoom.status === 'PLAYING' &&
            prev.game?.currentRound === pkt.hostedRoom.game?.currentRound &&
            prev.game?.chainCount === pkt.hostedRoom.game?.chainCount &&
            prev.game?.turnIndex === pkt.hostedRoom.game?.turnIndex &&
            prev.players?.length === pkt.hostedRoom.players?.length &&
            prev.spectators?.length === pkt.hostedRoom.spectators?.length;

          if (!sameActiveTurn) {
            roomsMap.set(pkt.hostedRoom.id, pkt.hostedRoom);
            renderRoomsList();
            if (myUser.roomId === pkt.hostedRoom.id) {
              renderRoomArena();
            }
          }
        }
        break;
      }

      case 'USER_LEAVE': {
        usersMap.delete(pkt.userId);
        renderLobbyUsers();
        break;
      }

      case 'LOBBY_CHAT': {
        appendLobbyChatLine(pkt.senderName, pkt.text);
        break;
      }

      case 'CUSTOM_WORD_ADDED': {
        if (pkt.entry) {
          DictionaryEngine.syncRemoteCustomWords([pkt.entry]);
          updateDictStatsUI();
        }
        break;
      }

      case 'ROOM_UPDATE': {
        if (!pkt.room) return;
        roomsMap.set(pkt.room.id, pkt.room);
        renderRoomsList();
        if (targetRoomToAutoJoin && targetRoomToAutoJoin === pkt.room.id) {
          const autoJoinId = targetRoomToAutoJoin;
          targetRoomToAutoJoin = null;
          setTimeout(() => {
            joinRoom(autoJoinId, false);
            showToast(`🎮 초대 링크를 통해 #${autoJoinId} 방에 입장했습니다!`);
          }, 300);
        }
        if (myUser.roomId === pkt.room.id) {
          renderRoomArena();
          if (pkt.sound) {
            triggerRemoteSound(pkt.sound);
          }
        }
        break;
      }

      case 'WORD_REJECTED': {
        if (myUser.roomId === pkt.roomId) {
          showWordRejectedFeedback(pkt.playerId, pkt.playerNickname, pkt.rawWord, pkt.reason);
        }
        break;
      }

      case 'ROOM_DELETED': {
        roomsMap.delete(pkt.roomId);
        if (myUser.roomId === pkt.roomId) {
          myUser.roomId = null;
          myUser.isSpectator = false;
          showView('LOBBY');
          showToast('방이 닫혔습니다.');
        }
        renderRoomsList();
        break;
      }

      case 'ROOM_CHAT': {
        if (myUser.roomId === pkt.roomId) {
          appendRoomChatLine(pkt.senderName, pkt.text, pkt.isSpectator, pkt.kind);
          if (pkt.senderId && !pkt.isSpectator && !pkt.kind) {
            showPlayerSpeechBubble(pkt.senderId, pkt.text);
          }
        }
        break;
      }

      case 'TYPING_PREVIEW': {
        if (myUser.roomId === pkt.roomId) {
          updateLiveTypingDisplay(pkt.playerId, pkt.text);
        }
        break;
      }

      case 'CLIENT_ACTION_REQ': {
        // 방장(Host)이 참가자/관전자의 요청을 처리
        const room = roomsMap.get(pkt.roomId);
        if (room && room.hostId === myUser.id) {
          handleClientRoomAction(room, pkt);
        }
        break;
      }
    }
  }

  function triggerRemoteSound(soundType) {
    if (soundType === 'WORD_OK') SoundFX.wordSuccess(false);
    else if (soundType === 'WORD_MISSION') SoundFX.wordSuccess(true);
    else if (soundType === 'WORD_ERR') SoundFX.wordError();
    else if (soundType === 'ROUND_FAIL') SoundFX.roundFail();
    else if (soundType === 'GAME_START') SoundFX.gameStart();
    else if (soundType === 'GAME_WIN') SoundFX.gameWin();
    else if (soundType === 'TURN_START') SoundFX.turnStart();
  }

  function pruneStaleUsers() {
    const now = Date.now();
    let changed = false;
    for (const [uid, u] of usersMap.entries()) {
      if (uid !== myUser.id && now - (u.lastSeen || 0) > 9000) {
        usersMap.delete(uid);
        changed = true;
      }
    }
    if (changed) renderLobbyUsers();
  }

  function getMyHostedRoomSnapshot() {
    if (!myUser.roomId) return null;
    const room = roomsMap.get(myUser.roomId);
    if (room && room.hostId === myUser.id) return room;
    return null;
  }

  // ==========================================
  // 3. 방 만들기 / 입장 / 관전 / 방장 권한 처리
  // ==========================================
  function createRoomFromModal() {
    const titleInput = document.getElementById('roomTitleInput').value.trim();
    const password = document.getElementById('roomPwInput').value.trim();
    const maxPlayers = parseInt(document.getElementById('roomMaxPlayers').value, 10) || 4;
    const totalRounds = parseInt(document.getElementById('roomRounds').value, 10) || 5;
    const roundTime = parseInt(document.getElementById('roomRoundTime').value, 10) || 60;
    const gameType = document.getElementById('roomGameType').value || 'KR_STD';

    const injeong = document.getElementById('ruleInjeong').checked;
    const dueum = document.getElementById('ruleDueum').checked;
    const manner = document.getElementById('ruleManner').checked;
    const noOneHit = document.getElementById('ruleNoOneHit').checked;
    const mission = document.getElementById('ruleMission').checked;
    const freeDict = document.getElementById('ruleFreeDict').checked;

    const selectedThemes = Array.from(document.querySelectorAll('.injeong-theme-chk:checked')).map(el => el.value);

    const rules = {
      gameType,
      injeong,
      injeongThemes: selectedThemes,
      dueum,
      manner,
      noOneHit,
      mission,
      freeDict
    };

    // 방 설정 수정 모드인 경우
    if (editingRoomMode && myUser.roomId) {
      const room = roomsMap.get(myUser.roomId);
      if (room && room.hostId === myUser.id && room.status === 'WAITING') {
        room.title = titleInput || `${myUser.nickname}님의 끝말잇기 방`;
        room.password = password;
        room.maxPlayers = maxPlayers;
        room.totalRounds = totalRounds;
        room.roundTime = roundTime;
        room.rules = rules;

        closeModal('createRoomModal');
        syncRoomState(room);
        sendRoomSystemChat(room.id, '⚙️ 방장이 방 규칙 및 설정을 변경했습니다.');
        return;
      }
    }

    const roomId = String(Math.floor(101 + Math.random() * 890));
    const newRoom = {
      id: roomId,
      title: titleInput || `${myUser.nickname}님의 즐거운 끄투방`,
      password: password,
      hostId: myUser.id,
      maxPlayers,
      totalRounds,
      roundTime,
      status: 'WAITING', // WAITING | PLAYING
      rules,
      players: [
        {
          id: myUser.id,
          nickname: myUser.nickname,
          avatar: myUser.avatar,
          score: 0,
          ready: true,
          isBot: false,
          lastWord: ''
        }
      ],
      spectators: [], // [{ id, nickname, avatar }]
      game: createEmptyGameState(roundTime)
    };

    roomsMap.set(roomId, newRoom);
    myUser.roomId = roomId;
    myUser.isSpectator = false;
    usersMap.set(myUser.id, { ...myUser });

    // 원격 접속을 위해 방장의 PeerJS 호스트 즉시 준비
    initPeerJSHost();

    closeModal('createRoomModal');
    showView('ROOM');
    clearRoomChatUI();
    sendRoomSystemChat(roomId, `👑 [${newRoom.title}] 방이 생성되었습니다! 우측 상단에서 AI 봇을 추가하거나 친구를 초대하세요.`);
    syncRoomState(newRoom);
  }

  function createEmptyGameState(roundTime = 60) {
    return {
      currentRound: 1,
      chainCount: 0,
      turnIndex: 0,
      roundTitleWord: '',
      targetChar: '',
      missionChar: '',
      roundTimeLeft: roundTime,
      roundTimeMax: roundTime,
      turnTimeLeft: 15,
      turnTimeMax: 15,
      usedWords: [], // 배열로 직렬화하여 네트워크 전송
      history: [],   // [{ word, playerNickname, meaning, isInjeong, theme, scoreDelta, missionHits }]
      lastBanner: '대기 중 — 모든 플레이어가 준비되면 게임을 시작하세요!'
    };
  }

  /**
   * 로비에서 방 입장 (참가자 또는 관전자)
   */
  function joinRoom(roomId, asSpectator = false) {
    const room = roomsMap.get(roomId);
    if (!room) {
      showToast('존재하지 않는 방입니다.');
      return;
    }

    // 비밀번호 확인 (관전자가 아니거나 비밀번호가 걸려 있을 때)
    if (room.password) {
      const inputPw = prompt(`🔒 비밀번호가 설정된 방입니다.\n비밀번호를 입력해 주세요:`);
      if (inputPw === null) return;
      if (inputPw !== room.password) {
        showToast('❌ 비밀번호가 일치하지 않습니다!');
        return;
      }
    }

    // 게임 진행 중인 방에 일반 참가를 시도하면 자동으로 관전 입장으로 안내
    if (!asSpectator && room.status === 'PLAYING') {
      asSpectator = true;
      showToast('👁️ 현재 게임이 진행 중이므로 관전자 모드로 입장합니다.');
    }

    // 인원 초과 시 관전으로 전환 여부 확인
    if (!asSpectator && room.players.length >= room.maxPlayers) {
      asSpectator = true;
      showToast('👁️ 방 정원이 가득 차서 관전자 모드로 입장합니다.');
    }

    myUser.roomId = roomId;
    myUser.isSpectator = asSpectator;
    usersMap.set(myUser.id, { ...myUser });

    clearRoomChatUI();
    showView('ROOM');

    if (room.hostId === myUser.id) {
      applyJoinToRoomObject(room, myUser, asSpectator);
      syncRoomState(room);
    } else {
      // 호스트에게 입장 요청 전송 + 로컬 즉시 반영
      applyJoinToRoomObject(room, myUser, asSpectator);
      renderRoomArena();
      broadcastPacket({
        type: 'CLIENT_ACTION_REQ',
        roomId: room.id,
        action: 'JOIN',
        user: myUser,
        asSpectator
      });
    }
  }

  function applyJoinToRoomObject(room, user, asSpectator) {
    room.players = room.players.filter(p => p.id !== user.id);
    room.spectators = room.spectators.filter(s => s.id !== user.id);

    if (asSpectator) {
      room.spectators.push({
        id: user.id,
        nickname: user.nickname,
        avatar: user.avatar
      });
    } else {
      room.players.push({
        id: user.id,
        nickname: user.nickname,
        avatar: user.avatar,
        score: 0,
        ready: room.hostId === user.id,
        isBot: false,
        lastWord: ''
      });
    }
  }

  /**
   * 방 안에서 [관전 전환 / 플레이어 참가 전환] 버튼 클릭
   */
  function toggleSpectatorMode() {
    if (!myUser.roomId) return;
    const room = roomsMap.get(myUser.roomId);
    if (!room) return;

    // 게임 진행 중에는 관전 -> 플레이어 난입 불가 (플레이어 -> 관전도 대기실에서만 허용)
    if (room.status === 'PLAYING') {
      showToast('게임 진행 중에는 관전/참가 상태를 변경할 수 없습니다. 라운드 종료 후 변경해 주세요.');
      return;
    }

    const targetSpectator = !myUser.isSpectator;
    if (!targetSpectator && room.players.length >= room.maxPlayers) {
      showToast('플레이어 슬롯이 가득 찼습니다!');
      return;
    }

    myUser.isSpectator = targetSpectator;
    usersMap.set(myUser.id, { ...myUser });

    if (room.hostId === myUser.id) {
      applyJoinToRoomObject(room, myUser, targetSpectator);
      syncRoomState(room);
      sendRoomSystemChat(room.id, targetSpectator
        ? `👁️ ${myUser.nickname}님이 관전자 석으로 이동했습니다.`
        : `🎮 ${myUser.nickname}님이 플레이어로 참가했습니다.`);
    } else {
      broadcastPacket({
        type: 'CLIENT_ACTION_REQ',
        roomId: room.id,
        action: 'TOGGLE_SPECTATE',
        user: myUser,
        asSpectator: targetSpectator
      });
    }
  }

  /**
   * 1-클릭 친구 초대 링크 복사 (Vercel 배포 시 카톡/디스코드에 바로 공유 가능)
   */
  function copyRoomInviteLink() {
    if (!myUser.roomId) {
      showToast('입장한 방이 없습니다.');
      return;
    }
    const room = roomsMap.get(myUser.roomId);
    if (!room) return;

    const btn = document.getElementById('btnCopyInviteLink');
    if (btn) btn.textContent = '⏳ 링크 생성중...';

    const finishCopy = (code) => {
      const url = `${window.location.origin}${window.location.pathname}?room=${encodeURIComponent(room.id)}&host=${encodeURIComponent(code)}`;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url).then(() => {
          showToast(`📋 방 #${room.id} 1-클릭 초대 링크가 복사되었습니다! 친구들에게 공유하세요.`);
          if (btn) btn.textContent = '✅ 복사 완료!';
          setTimeout(() => { if (btn) btn.textContent = '🔗 링크 복사'; }, 2000);
        }).catch(() => {
          prompt('아래 초대 링크를 복사하여 친구들에게 전달하세요:', url);
          if (btn) btn.textContent = '🔗 링크 복사';
        });
      } else {
        prompt('아래 초대 링크를 복사하여 친구들에게 전달하세요:', url);
        if (btn) btn.textContent = '🔗 링크 복사';
      }
    };

    const targetCode = room.hostPeerCode || (room.hostId === myUser.id ? myInviteCode : null);
    if (targetCode) {
      finishCopy(targetCode);
    } else {
      initPeerJSHost((code) => {
        room.hostPeerCode = code;
        syncRoomState(room);
        finishCopy(code);
      });
    }
  }

  function leaveCurrentRoom(silent = false) {
    if (!myUser.roomId) return;
    const roomId = myUser.roomId;
    const room = roomsMap.get(roomId);

    stopHostGameTimers();
    myUser.roomId = null;
    myUser.isSpectator = false;
    usersMap.set(myUser.id, { ...myUser });

    if (room) {
      if (room.hostId === myUser.id) {
        // 인간 플레이어가 남아 있으면 방장 위임, 없으면 방 삭제
        room.players = room.players.filter(p => p.id !== myUser.id);
        room.spectators = room.spectators.filter(s => s.id !== myUser.id);
        const nextHuman = room.players.find(p => !p.isBot) || room.spectators[0];

        if (nextHuman) {
          room.hostId = nextHuman.id;
          // 관전자였다면 플레이어로 승격
          if (!room.players.some(p => p.id === nextHuman.id)) {
            room.spectators = room.spectators.filter(s => s.id !== nextHuman.id);
            room.players.unshift({
              id: nextHuman.id,
              nickname: nextHuman.nickname,
              avatar: nextHuman.avatar,
              score: 0,
              ready: true,
              isBot: false,
              lastWord: ''
            });
          } else {
            const p = room.players.find(pl => pl.id === nextHuman.id);
            if (p) p.ready = true;
          }
          syncRoomState(room);
          sendRoomSystemChat(roomId, `👑 방장이 퇴장하여 ${nextHuman.nickname}님에게 방장이 위임되었습니다.`);
        } else {
          roomsMap.delete(roomId);
          broadcastPacket({ type: 'ROOM_DELETED', roomId });
        }
      } else {
        broadcastPacket({
          type: 'CLIENT_ACTION_REQ',
          roomId,
          action: 'LEAVE',
          userId: myUser.id,
          nickname: myUser.nickname
        });
      }
    }

    if (!silent) {
      showView('LOBBY');
      renderRoomsList();
      renderLobbyUsers();
    }
  }

  /**
   * 호스트(방장)가 원격 참가자의 액션 요청을 처리
   */
  function handleClientRoomAction(room, pkt) {
    switch (pkt.action) {
      case 'JOIN': {
        applyJoinToRoomObject(room, pkt.user, pkt.asSpectator);
        syncRoomState(room);
        sendRoomSystemChat(
          room.id,
          pkt.asSpectator
            ? `👁️ ${pkt.user.nickname}님이 관전자로 입장하셨습니다.`
            : `👋 ${pkt.user.nickname}님이 방에 입장하셨습니다!`
        );
        break;
      }
      case 'TOGGLE_SPECTATE': {
        applyJoinToRoomObject(room, pkt.user, pkt.asSpectator);
        syncRoomState(room);
        sendRoomSystemChat(
          room.id,
          pkt.asSpectator
            ? `👁️ ${pkt.user.nickname}님이 관전자 석으로 이동했습니다.`
            : `🎮 ${pkt.user.nickname}님이 플레이어로 참가했습니다.`
        );
        break;
      }
      case 'LEAVE': {
        room.players = room.players.filter(p => p.id !== pkt.userId);
        room.spectators = room.spectators.filter(s => s.id !== pkt.userId);
        syncRoomState(room);
        sendRoomSystemChat(room.id, `🚪 ${pkt.nickname || '유저'}님이 퇴장하셨습니다.`);
        break;
      }
      case 'READY_TOGGLE': {
        const p = room.players.find(pl => pl.id === pkt.userId);
        if (p) {
          p.ready = !p.ready;
          syncRoomState(room);
        }
        break;
      }
      case 'SUBMIT_WORD': {
        processPlayerWordSubmission(room, pkt.userId, pkt.word);
        break;
      }
    }
  }

  // ==========================================
  // 4. AI 봇 추가 / 제거 및 자동 끝말잇기 인공지능
  // ==========================================
  function addBotToRoom(level = 'NORMAL') {
    if (!myUser.roomId) return;
    const room = roomsMap.get(myUser.roomId);
    if (!room || room.hostId !== myUser.id) return;
    if (room.status === 'PLAYING') {
      showToast('게임 대기 중에만 봇을 추가할 수 있습니다.');
      return;
    }
    if (room.players.length >= room.maxPlayers) {
      showToast('방 최대 인원이 가득 찼습니다!');
      return;
    }

    const levelNames = { EASY: '초보봇', NORMAL: '숙련봇', HARD: '끝말박사봇' };
    const botAvatars = { EASY: '🐥', NORMAL: '🤖', HARD: '🐲' };
    const botId = 'bot_' + Math.random().toString(36).slice(2, 7);
    const botNum = room.players.filter(p => p.isBot).length + 1;

    room.players.push({
      id: botId,
      nickname: `${levelNames[level] || '끄투봇'}#${botNum}`,
      avatar: botAvatars[level] || '🤖',
      score: 0,
      ready: true,
      isBot: true,
      botLevel: level,
      lastWord: ''
    });

    syncRoomState(room);
    sendRoomSystemChat(room.id, `🤖 인공지능 [${levelNames[level]}#${botNum}]이(가) 참가했습니다.`);
  }

  function removeBotsFromRoom() {
    if (!myUser.roomId) return;
    const room = roomsMap.get(myUser.roomId);
    if (!room || room.hostId !== myUser.id || room.status === 'PLAYING') return;

    const before = room.players.length;
    room.players = room.players.filter(p => !p.isBot);
    if (room.players.length < before) {
      syncRoomState(room);
      sendRoomSystemChat(room.id, '🧹 모든 AI 봇을 내보냈습니다.');
    }
  }

  // ==========================================
  // 5. 원본 끄투 핵심 게임 진행 로직 (호스트 권위 엔진)
  // ==========================================
  function onReadyOrStartClick() {
    if (!myUser.roomId) return;
    const room = roomsMap.get(myUser.roomId);
    if (!room) return;

    if (myUser.isSpectator) {
      showToast('관전자는 준비/시작을 누를 수 없습니다. 상단 [참가 전환]을 눌러주세요.');
      return;
    }

    if (room.hostId === myUser.id) {
      startGame(room);
    } else {
      broadcastPacket({
        type: 'CLIENT_ACTION_REQ',
        roomId: room.id,
        action: 'READY_TOGGLE',
        userId: myUser.id
      });
    }
  }

  function startGame(room) {
    if (room.players.length < 2) {
      showToast('⚠️ 최소 2명 이상의 플레이어가 필요합니다! (혼자 테스트하려면 상단 [+봇 추가]를 눌러보세요)');
      return;
    }
    const notReady = room.players.find(p => p.id !== room.hostId && !p.isBot && !p.ready);
    if (notReady) {
      showToast(`⚠️ 아직 준비하지 않은 플레이어가 있습니다: ${notReady.nickname}`);
      return;
    }

    room.status = 'PLAYING';
    room.players.forEach(p => {
      p.score = 0;
      p.lastWord = '';
    });

    room.game = createEmptyGameState(room.roundTime);
    room.game.currentRound = 1;
    room.game.turnIndex = 0;
    // 원본 끄투 방식: 라운드 수에 맞는 제시어 단어 선정 (예: 5라운드 -> '아이스크림')
    room.game.roundTitleWord = DictionaryEngine.pickRoundTitleWord(room.totalRounds, room.rules);

    startNewRound(room, 1);
  }

  function startNewRound(room, roundNum) {
    stopHostGameTimers();

    room.game.currentRound = roundNum;
    room.game.chainCount = 0;
    room.game.history = [];
    room.game.roundTimeLeft = room.roundTime;
    room.game.roundTimeMax = room.roundTime;

    // 원본 끄투 방식: 상단 라운드 제시어의 해당 라운드 글자로 시작
    const titleWord = room.game.roundTitleWord || '';
    const roundChar = titleWord[roundNum - 1];
    room.game.targetChar = roundChar || DictionaryEngine.pickStartingChar(room.rules);

    room.game.missionChar = room.rules.mission ? DictionaryEngine.pickMissionChar() : '';
    room.game.turnTimeMax = computeTurnTimeMax(room.roundTime, 0);
    room.game.turnTimeLeft = room.game.turnTimeMax;

    const currentPlayer = room.players[room.game.turnIndex % room.players.length];
    const formattedTarget = Hangul.formatTargetChar(room.game.targetChar, room.rules.dueum);
    room.game.lastBanner = `🔔 ROUND ${roundNum} (${titleWord ? titleWord.split('').join('·') : formattedTarget}) — '${formattedTarget}'(으)로 시작! (${currentPlayer.nickname}님 차례)`;

    SoundFX.gameStart();
    syncRoomState(room, 'GAME_START');
    sendRoomSystemChat(
      room.id,
      `🏁 [ROUND ${roundNum} / ${room.totalRounds}] 제시어 [${titleWord || formattedTarget}] 중 '${formattedTarget}'(으)로 시작합니다!${room.game.missionChar ? ` (🎯 미션 글자: ${room.game.missionChar})` : ''}`,
      'game-event'
    );

    startHostLoop(room);
    scheduleBotTurnIfNeeded(room);
  }

  /**
   * 체인이 길어질수록 턴 시간이 점점 짧아지는 원본 끄투 스피드 공식
   */
  function computeTurnTimeMax(roundTimeLeft, chainCount) {
    // 기본 14초에서 체인이 쌓일수록 1.8초까지 단축, 남은 라운드 시간을 초과하지 않음
    const base = Math.max(2.0, 14 - chainCount * 0.45);
    return Math.min(base, Math.max(1.5, roundTimeLeft));
  }

  /**
   * 모든 클라이언트(방장 및 참가자)에서 부드럽게 타이머 게이지만 갱신하는 루프
   * (0.4초마다 전체 DOM을 재렌더링하던 문제를 제거하여 한글 조합 깨짐 및 말풍선 증발 완벽 방지)
   */
  function startClientSmoothTimerLoop() {
    setInterval(() => {
      if (!myUser.roomId) return;
      const room = roomsMap.get(myUser.roomId);
      if (!room || room.status !== 'PLAYING' || !room.game) return;

      // 방장이 아닌 클라이언트도 로컬에서 부드럽게 타이머 감소
      if (room.hostId !== myUser.id) {
        room.game.turnTimeLeft = Math.max(0, +(room.game.turnTimeLeft - 0.1).toFixed(2));
        room.game.roundTimeLeft = Math.max(0, +(room.game.roundTimeLeft - 0.1).toFixed(2));
        updateTimerBarsDOM(room);

        const secFloor = Math.ceil(room.game.turnTimeLeft);
        if (secFloor <= 3 && secFloor > 0 && secFloor !== lastTickSecond) {
          lastTickSecond = secFloor;
          SoundFX.tick(true);
        }
      }
    }, 100);
  }

  function startHostLoop(room) {
    stopHostGameTimers();
    lastTickSecond = -1;

    hostGameInterval = setInterval(() => {
      if (!roomsMap.has(room.id) || room.status !== 'PLAYING') {
        stopHostGameTimers();
        return;
      }

      room.game.turnTimeLeft = Math.max(0, +(room.game.turnTimeLeft - 0.1).toFixed(2));
      room.game.roundTimeLeft = Math.max(0, +(room.game.roundTimeLeft - 0.1).toFixed(2));

      // 로컬 타이머 게이지만 즉시 갱신 (네트워크 전체 재렌더링 스팸 금지)
      updateTimerBarsDOM(room);

      const secFloor = Math.ceil(room.game.turnTimeLeft);
      if (secFloor <= 3 && secFloor > 0 && secFloor !== lastTickSecond) {
        lastTickSecond = secFloor;
        SoundFX.tick(true);
      }

      if (room.game.turnTimeLeft <= 0 || room.game.roundTimeLeft <= 0) {
        handleRoundTimeout(room);
      }
    }, 100);
  }

  function stopHostGameTimers() {
    if (hostGameInterval) {
      clearInterval(hostGameInterval);
      hostGameInterval = null;
    }
    if (botActionTimeout) {
      clearTimeout(botActionTimeout);
      botActionTimeout = null;
    }
  }

  function handleRoundTimeout(room) {
    stopHostGameTimers();
    const loser = room.players[room.game.turnIndex % room.players.length];
    const penalty = Math.min(loser.score, 60);
    loser.score = Math.max(0, loser.score - penalty);

    SoundFX.roundFail();
    room.game.lastBanner = `💥 시간 초과! ${loser.nickname}님이 단어를 잇지 못했습니다. (-${penalty}점)`;
    sendRoomSystemChat(
      room.id,
      `💥 [라운드 종료] ${loser.nickname}님이 제한시간 내에 단어를 입력하지 못했습니다! (-${penalty}점)`,
      'error-msg'
    );
    syncRoomState(room, 'ROUND_FAIL');

    if (room.game.currentRound >= room.totalRounds) {
      setTimeout(() => finishGame(room), 2200);
    } else {
      // 다음 라운드는 패배한 사람 다음 사람부터 시작
      room.game.turnIndex = (room.game.turnIndex + 1) % room.players.length;
      setTimeout(() => {
        if (room.status === 'PLAYING') {
          startNewRound(room, room.game.currentRound + 1);
        }
      }, 2400);
    }
  }

  function finishGame(room) {
    stopHostGameTimers();
    room.status = 'WAITING';
    room.players.forEach(p => {
      if (!p.isBot && p.id !== room.hostId) p.ready = false;
    });

    const sorted = [...room.players].sort((a, b) => b.score - a.score);
    const winner = sorted[0];

    room.game.lastBanner = `🏆 게임 종료! 최종 우승: ${winner ? winner.nickname : '없음'} (${winner ? winner.score : 0}점)`;
    SoundFX.gameWin();
    syncRoomState(room, 'GAME_WIN');

    if (winner) {
      sendRoomSystemChat(
        room.id,
        `🏆 [게임 종료] 1위: ${winner.nickname} (${winner.score}점)! 축하합니다!`,
        'game-event'
      );
      if (winner.id === myUser.id) {
        myUser.wins += 1;
        myUser.totalScore += winner.score;
        saveProfile();
        renderProfileHeader();
      }
    }

    showGameResultModal(sorted);
  }

  /**
   * 플레이어(또는 봇)의 단어 제출 판정 처리
   */
  function processPlayerWordSubmission(room, playerId, rawWord) {
    if (room.status !== 'PLAYING') return;
    const activePlayer = room.players[room.game.turnIndex % room.players.length];
    if (!activePlayer || activePlayer.id !== playerId) return;

    const usedSet = new Set(room.game.usedWords);
    const validation = DictionaryEngine.validateWordSubmission(
      rawWord,
      room.game.targetChar,
      room.rules,
      usedSet,
      room.game.chainCount
    );

    if (!validation.valid) {
      // 원본 끄투 스타일 오답/규칙 위반 처리: 전광판을 흔들고 1.1초 뒤 원래 제시어로 복구하여 즉시 재입력 가능하게 함
      showWordRejectedFeedback(activePlayer.id, activePlayer.nickname, rawWord, validation.message);
      broadcastPacket({
        type: 'WORD_REJECTED',
        roomId: room.id,
        playerId: activePlayer.id,
        playerNickname: activePlayer.nickname,
        rawWord,
        reason: validation.message
      });
      return;
    }

    // 정답 처리 및 원본 끄투 스타일 점수 산정
    const word = validation.entry.word;
    room.game.usedWords.push(word);
    room.game.chainCount += 1;

    // 미션 글자 포함 횟수 계산
    let missionHits = 0;
    if (room.rules.mission && room.game.missionChar) {
      for (const ch of word) {
        if (ch === room.game.missionChar) missionHits++;
      }
    }

    // 점수 공식: 기본 글자 점수 + 속도 보너스 + 체인 보너스 + 미션 보너스 + 어인정 보너스
    const lengthScore = word.length * 14;
    const speedRatio = room.game.turnTimeLeft / Math.max(1, room.game.turnTimeMax);
    const speedBonus = Math.round(speedRatio * 24);
    const chainBonus = Math.min(40, room.game.chainCount * 3);
    const missionBonus = missionHits * 55;
    const injeongBonus = validation.entry.isInjeong ? 15 : 0;
    const scoreDelta = lengthScore + speedBonus + chainBonus + missionBonus + injeongBonus;

    activePlayer.score += scoreDelta;
    activePlayer.lastWord = word;

    // 미션 글자 달성 시 새로운 미션 글자 갱신
    const prevMissionChar = room.game.missionChar;
    if (missionHits > 0 && room.rules.mission) {
      room.game.missionChar = DictionaryEngine.pickMissionChar();
    }

    // 히스토리 추가
    const histItem = {
      word,
      playerNickname: activePlayer.nickname,
      meaning: validation.entry.meaning,
      isInjeong: validation.entry.isInjeong,
      theme: validation.entry.theme,
      scoreDelta,
      missionHits,
      missionCharUsed: prevMissionChar
    };
    room.game.history.push(histItem);
    if (room.game.history.length > 25) {
      room.game.history.shift();
    }

    // 다음 타겟 글자 및 턴 이동
    room.game.targetChar = validation.nextChar;
    room.game.turnIndex = (room.game.turnIndex + 1) % room.players.length;
    room.game.turnTimeMax = computeTurnTimeMax(room.game.roundTimeLeft, room.game.chainCount);
    room.game.turnTimeLeft = room.game.turnTimeMax;

    const nextPlayer = room.players[room.game.turnIndex % room.players.length];
    const missionText = missionHits > 0 ? ` 🎯 미션(${prevMissionChar}×${missionHits}) 달성! (+${missionBonus}점)` : '';
    const injeongThemeObj = DictionaryEngine.INJEONG_THEMES[validation.entry.theme];
    const injeongTagText = validation.entry.isInjeong
      ? ` [어인정: ${injeongThemeObj ? injeongThemeObj.name : '커스텀'}]`
      : '';

    room.game.lastBanner = `✅ ${activePlayer.nickname}: '${word}' (+${scoreDelta}점)${missionText} ➔ 다음: ${nextPlayer.nickname}님 차례!`;

    const soundKey = missionHits > 0 ? 'WORD_MISSION' : 'WORD_OK';
    triggerRemoteSound(soundKey);
    syncRoomState(room, soundKey);

    sendRoomSystemChat(
      room.id,
      `✨ [${activePlayer.nickname}] '${word}'${injeongTagText} (+${scoreDelta}점)${missionText} — 뜻: ${validation.entry.meaning}`
    );

    // 만약 한방단어 방지/매너모드가 꺼져 있고, 실제로 이어질 단어가 0개인 절대 한방단어를 성공시켰다면?
    if (validation.remainingFollowUps === 0 && !room.rules.freeDict) {
      sendRoomSystemChat(
        room.id,
        `⚡ 경고! '${ Hangul.formatTargetChar(room.game.targetChar, room.rules.dueum) }'(으)로 이어질 수 있는 사전 단어가 남아있지 않습니다!`,
        'game-event'
      );
    }

    scheduleBotTurnIfNeeded(room);
  }

  /**
   * 현재 턴이 AI 봇인 경우 실시간 타이핑 애니메이션 후 단어 제출
   */
  function scheduleBotTurnIfNeeded(room) {
    if (botActionTimeout) {
      clearTimeout(botActionTimeout);
      botActionTimeout = null;
    }
    if (room.status !== 'PLAYING' || room.hostId !== myUser.id) return;

    const currentPlayer = room.players[room.game.turnIndex % room.players.length];
    if (!currentPlayer || !currentPlayer.isBot) {
      // 내 차례가 시작되었을 때 알림음 & 전광판 전용 단어 입력창 포커스
      if (currentPlayer && currentPlayer.id === myUser.id) {
        SoundFX.turnStart();
        const inputEl = document.getElementById('arenaWordInput');
        if (inputEl) {
          inputEl.disabled = false;
          inputEl.focus();
        }
      }
      return;
    }

    const usedSet = new Set(room.game.usedWords);
    const candidates = DictionaryEngine.getFollowUpWords(room.game.targetChar, room.rules, usedSet);

    // 방 규칙(한방방지/매너모드/첫턴한방)을 통과하는 후보 단어만 필터링
    const validCandidates = candidates.filter(entry => {
      const check = DictionaryEngine.validateWordSubmission(
        entry.word,
        room.game.targetChar,
        room.rules,
        usedSet,
        room.game.chainCount
      );
      return check.valid;
    });

    if (validCandidates.length === 0) {
      // 이을 단어가 없으면 봇이 고민하는 대사를 치고 타임아웃 대기
      botActionTimeout = setTimeout(() => {
        showPlayerSpeechBubble(currentPlayer.id, '헉.. 단어가 생각이 안 나요 ㅠㅠ');
        broadcastPacket({
          type: 'ROOM_CHAT',
          roomId: room.id,
          senderId: currentPlayer.id,
          senderName: currentPlayer.nickname,
          text: '헉.. 이을 수 있는 단어가 없네요 ㅠㅠ'
        });
      }, 900);
      return;
    }

    // 난이도별 단어 선택
    let chosenEntry = validCandidates[Math.floor(Math.random() * validCandidates.length)];
    if (currentPlayer.botLevel === 'HARD' && room.game.missionChar) {
      const missionMatches = validCandidates.filter(e => e.word.includes(room.game.missionChar));
      if (missionMatches.length > 0) {
        chosenEntry = missionMatches[Math.floor(Math.random() * missionMatches.length)];
      }
    } else if (currentPlayer.botLevel === 'EASY') {
      const shortMatches = validCandidates.filter(e => e.word.length <= 3);
      if (shortMatches.length > 0) {
        chosenEntry = shortMatches[Math.floor(Math.random() * shortMatches.length)];
      }
    }

    const wordToType = chosenEntry.word;
    const thinkDelay = currentPlayer.botLevel === 'HARD' ? 650 : currentPlayer.botLevel === 'NORMAL' ? 1050 : 1450;

    botActionTimeout = setTimeout(() => {
      if (room.status !== 'PLAYING') return;
      let step = 1;
      const stepInterval = setInterval(() => {
        if (room.status !== 'PLAYING') {
          clearInterval(stepInterval);
          return;
        }
        if (step <= wordToType.length) {
          const partial = wordToType.slice(0, step);
          updateLiveTypingDisplay(currentPlayer.id, partial);
          broadcastPacket({
            type: 'TYPING_PREVIEW',
            roomId: room.id,
            playerId: currentPlayer.id,
            text: partial
          });
          step++;
        } else {
          clearInterval(stepInterval);
          processPlayerWordSubmission(room, currentPlayer.id, wordToType);
        }
      }, 180);
    }, thinkDelay);
  }

  function syncRoomState(room, sound = null) {
    if (myInviteCode && room.hostId === myUser.id) {
      room.hostPeerCode = myInviteCode;
    }
    roomsMap.set(room.id, room);
    renderRoomsList();
    if (myUser.roomId === room.id) {
      renderRoomArena();
    }
    broadcastPacket({
      type: 'ROOM_UPDATE',
      room,
      sound
    });
  }

  // ==========================================
  // 6. UI 렌더링 및 이벤트 바인딩
  // ==========================================
  function bindUIEvents() {
    // 테마 변경 셀렉트
    const themeSel = document.getElementById('themeSelect');
    if (themeSel) {
      themeSel.addEventListener('change', (e) => {
        applyTheme(e.target.value);
      });
    }

    // 사운드 음소거 토글
    document.getElementById('btnToggleSound').addEventListener('click', () => {
      const muted = SoundFX.toggleMute();
      document.getElementById('btnToggleSound').textContent = muted ? '🔇 음소거' : '🔊 효과음';
    });

    // 내 프로필 변경 모달 열기
    document.getElementById('myProfilePill').addEventListener('click', openProfileModal);
    document.getElementById('btnSaveProfile').addEventListener('click', saveProfileFromModal);

    // 원격 연결 모달 열기
    const openRemoteInviteModal = () => {
      openModal('remoteConnectModal');
      updateInviteModalLinkDisplay(myInviteCode);
      if (!myInviteCode) {
        initPeerJSHost();
      }
    };
    document.getElementById('netStatusPill')?.addEventListener('click', openRemoteInviteModal);
    document.getElementById('btnOpenRemoteModal')?.addEventListener('click', openRemoteInviteModal);

    // 모달 내 1-클릭 링크 복사 버튼
    document.getElementById('btnCopyModalLink')?.addEventListener('click', () => {
      const input = document.getElementById('modalInviteLinkInput');
      const btn = document.getElementById('btnCopyModalLink');
      if (!input || !input.value) return;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(input.value).then(() => {
          showToast('📋 초대 링크가 복사되었습니다! 친구들에게 공유하세요.');
          if (btn) btn.textContent = '✅ 복사 완료!';
          setTimeout(() => { if (btn) btn.textContent = '📋 링크 복사'; }, 2000);
        }).catch(() => {
          prompt('아래 초대 링크를 복사하여 친구들에게 전달하세요:', input.value);
        });
      } else {
        prompt('아래 초대 링크를 복사하여 친구들에게 전달하세요:', input.value);
      }
    });

    document.getElementById('btnConnectFriendCode')?.addEventListener('click', () => {
      const inputVal = document.getElementById('friendCodeInput')?.value;
      connectToRemotePeer(inputVal);
    });

    // 단어장 모달 열기 & 검색 & 추가
    document.getElementById('btnOpenDictModal').addEventListener('click', () => {
      openModal('dictManagerModal');
      renderDictionarySearchList();
    });
    document.getElementById('dictSearchInput').addEventListener('input', renderDictionarySearchList);
    document.getElementById('dictFilterSelect').addEventListener('change', renderDictionarySearchList);
    document.getElementById('btnAddCustomWord').addEventListener('click', handleAddCustomWordUI);

    // 방 만들기 모달 열기
    document.getElementById('btnOpenCreateRoom').addEventListener('click', () => {
      editingRoomMode = false;
      document.getElementById('createRoomModalTitle').textContent = '➕ 새로운 끝말잇기 방 만들기';
      document.getElementById('btnConfirmCreateRoom').textContent = '방 만들기';
      openModal('createRoomModal');
    });

    // 빠른 입장
    document.getElementById('btnQuickJoin').addEventListener('click', () => {
      const waitingRoom = Array.from(roomsMap.values()).find(r => r.status === 'WAITING' && !r.password && r.players.length < r.maxPlayers);
      if (waitingRoom) {
        joinRoom(waitingRoom.id, false);
      } else {
        const anyRoom = Array.from(roomsMap.values())[0];
        if (anyRoom) {
          joinRoom(anyRoom.id, true);
        } else {
          document.getElementById('btnOpenCreateRoom').click();
        }
      }
    });

    // 방 필터 버튼
    document.querySelectorAll('.room-filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        currentRoomFilter = btn.dataset.filter || 'ALL';
        document.querySelectorAll('.room-filter-btn').forEach(b => b.classList.remove('btn-primary'));
        btn.classList.add('btn-primary');
        renderRoomsList();
      });
    });

    // 방 만들기 폼 제출
    document.getElementById('btnConfirmCreateRoom').addEventListener('click', createRoomFromModal);

    // 어인정 체크박스 토글 시 하위 주제 영역 표시/숨김
    document.getElementById('ruleInjeong').addEventListener('change', (e) => {
      const box = document.getElementById('injeongThemesWrap');
      box.style.opacity = e.target.checked ? '1' : '0.4';
    });

    // 로비 채팅 입력
    const lobbyInput = document.getElementById('lobbyChatInput');
    document.getElementById('btnSendLobbyChat').addEventListener('click', sendLobbyChat);
    lobbyInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') sendLobbyChat();
    });

    // 게임 방 상단 버튼들
    document.getElementById('btnLeaveRoom').addEventListener('click', () => leaveCurrentRoom(false));
    document.getElementById('btnToggleSpectate').addEventListener('click', toggleSpectatorMode);
    document.getElementById('btnReadyOrStart').addEventListener('click', onReadyOrStartClick);
    document.getElementById('btnRoomSettings').addEventListener('click', openEditRoomModal);
    document.getElementById('btnCopyInviteLink')?.addEventListener('click', copyRoomInviteLink);

    const btnAddBot = document.getElementById('btnAddBot');
    if (btnAddBot) {
      btnAddBot.addEventListener('click', () => {
        const level = document.getElementById('botLevelSelect')?.value || 'NORMAL';
        addBotToRoom(level);
      });
    }
    document.getElementById('btnRemoveBots').addEventListener('click', removeBotsFromRoom);

    // ★ 1) 전광판 내부 전용 끝말잇기 단어 입력창 (#arenaWordInput)
    const arenaWordInput = document.getElementById('arenaWordInput');
    arenaWordInput.addEventListener('input', () => {
      if (!myUser.roomId) return;
      const room = roomsMap.get(myUser.roomId);
      if (!room || room.status !== 'PLAYING' || myUser.isSpectator) return;
      const activePlayer = room.players[room.game.turnIndex % room.players.length];
      if (activePlayer && activePlayer.id === myUser.id) {
        const text = arenaWordInput.value.trim();
        updateLiveTypingDisplay(myUser.id, text);
        broadcastPacket({
          type: 'TYPING_PREVIEW',
          roomId: room.id,
          playerId: myUser.id,
          text
        });
      }
    });

    arenaWordInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleArenaWordSubmit();
      }
    });

    document.getElementById('btnArenaWordSubmit').addEventListener('click', handleArenaWordSubmit);

    // ★ 2) 하단 순수 채팅 전용 입력창 (#roomChatInput)
    const roomChatInput = document.getElementById('roomChatInput');
    roomChatInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        handleRoomChatSubmit();
      }
    });
    document.getElementById('btnSendRoomChat').addEventListener('click', handleRoomChatSubmit);

    // 모달 닫기 버튼 공통
    document.querySelectorAll('[data-close-modal]').forEach(btn => {
      btn.addEventListener('click', () => closeModal(btn.dataset.closeModal));
    });

    // ★ 원본 끄투 단축키: 방 안에서 아무 입력창에도 포커스가 없을 때 Enter를 누르면 내 턴이면 단어입력창, 아니면 채팅창으로 즉시 포커스
    window.addEventListener('keydown', (e) => {
      if (e.key !== 'Enter') return;
      const activeTag = document.activeElement ? document.activeElement.tagName : '';
      if (activeTag === 'INPUT' || activeTag === 'TEXTAREA' || activeTag === 'SELECT' || activeTag === 'BUTTON') {
        return;
      }
      if (!myUser.roomId) return;
      const room = roomsMap.get(myUser.roomId);
      if (!room) return;
      const activePlayer = room.status === 'PLAYING'
        ? room.players[room.game.turnIndex % room.players.length]
        : null;
      const isMyTurn = Boolean(activePlayer && activePlayer.id === myUser.id && !myUser.isSpectator);
      if (isMyTurn) {
        document.getElementById('arenaWordInput')?.focus();
      } else {
        document.getElementById('roomChatInput')?.focus();
      }
    });
  }

  /**
   * 전광판 끝말잇기 단어 전용 제출 핸들러
   */
  function handleArenaWordSubmit() {
    if (!myUser.roomId) return;
    const room = roomsMap.get(myUser.roomId);
    if (!room || room.status !== 'PLAYING') {
      showToast('아직 게임이 시작되지 않았습니다.');
      return;
    }
    if (myUser.isSpectator) {
      showToast('관전자는 단어를 입력할 수 없습니다.');
      return;
    }

    const activePlayer = room.players[room.game.turnIndex % room.players.length];
    if (!activePlayer || activePlayer.id !== myUser.id) {
      showToast('아직 내 차례가 아닙니다! 일반 대화는 아래 채팅창을 이용해 주세요.');
      return;
    }

    const inputEl = document.getElementById('arenaWordInput');
    const rawWord = inputEl.value.trim();
    if (!rawWord) return;
    inputEl.value = '';
    inputEl.focus();

    if (room.hostId === myUser.id) {
      processPlayerWordSubmission(room, myUser.id, rawWord);
    } else {
      broadcastPacket({
        type: 'CLIENT_ACTION_REQ',
        roomId: room.id,
        action: 'SUBMIT_WORD',
        userId: myUser.id,
        word: rawWord
      });
    }
  }

  /**
   * 하단 방 채팅 전용 전송 핸들러
   */
  function handleRoomChatSubmit() {
    if (!myUser.roomId) return;
    const room = roomsMap.get(myUser.roomId);
    if (!room) return;

    const inputEl = document.getElementById('roomChatInput');
    const chatText = inputEl.value.trim();
    if (!chatText) return;
    inputEl.value = '';

    appendRoomChatLine(myUser.nickname, chatText, myUser.isSpectator);
    if (!myUser.isSpectator) {
      showPlayerSpeechBubble(myUser.id, chatText);
    }
    broadcastPacket({
      type: 'ROOM_CHAT',
      roomId: room.id,
      senderId: myUser.id,
      senderName: myUser.nickname,
      text: chatText,
      isSpectator: myUser.isSpectator
    });
  }

  // ==========================================
  // 7. 화면 렌더링 함수들
  // ==========================================
  function showView(viewName) {
    const lobbyEl = document.getElementById('lobbyView');
    const roomEl = document.getElementById('roomView');
    if (viewName === 'ROOM') {
      lobbyEl.classList.add('hidden');
      roomEl.classList.remove('hidden');
      renderRoomArena();
    } else {
      roomEl.classList.add('hidden');
      lobbyEl.classList.remove('hidden');
      renderRoomsList();
      renderLobbyUsers();
    }
  }

  function renderProfileHeader() {
    document.getElementById('myAvatarTop').textContent = myUser.avatar;
    document.getElementById('myNicknameTop').textContent = myUser.nickname;
    document.getElementById('myStatsTop').textContent = `${myUser.wins}승 · ${myUser.totalScore.toLocaleString()}점`;
  }

  function updateNetStatusPill(text) {
    document.getElementById('netStatusText').textContent = text;
  }

  function renderLobbyUsers() {
    const listEl = document.getElementById('lobbyUsersList');
    const countEl = document.getElementById('onlineUserCount');
    const allUsers = Array.from(usersMap.values());
    countEl.textContent = `${allUsers.length}명`;

    listEl.innerHTML = allUsers.map(u => {
      let badgeHtml = `<span class="user-status-badge status-lobby">로비</span>`;
      if (u.roomId) {
        badgeHtml = u.isSpectator
          ? `<span class="user-status-badge status-spectate">#${u.roomId} 관전중</span>`
          : `<span class="user-status-badge status-room">#${u.roomId} 참가중</span>`;
      }
      const meTag = u.id === myUser.id ? ' <small style="opacity:0.75;">(나)</small>' : '';
      return `
        <div class="user-item">
          <div class="user-item-left">
            <span>${escapeHtml(u.avatar || '🦊')}</span>
            <span>${escapeHtml(u.nickname)}${meTag}</span>
          </div>
          ${badgeHtml}
        </div>
      `;
    }).join('');
  }

  function formatGameTypeLabel(gameType) {
    if (gameType === 'KKT') return '한국어 쿵쿵따 (3글자)';
    if (gameType === 'FRONT') return '한국어 앞말잇기';
    return '한국어 끝말잇기';
  }

  function buildRuleBadgesHTML(rules = {}) {
    const badges = [];
    if (rules.injeong) {
      badges.push(`<span class="rule-badge rb-injeong" title="어인정 어휘(게임/애니/브랜드/밈 등) 허용">🟣 어인정 ON</span>`);
    }
    if (rules.dueum !== false) {
      badges.push(`<span class="rule-badge rb-dueum" title="두음법칙 자동 허용 (예: 름→늠, 량→양)">🟢 두음법칙</span>`);
    } else {
      badges.push(`<span class="rule-badge rb-dueum-off" title="두음법칙 금지 하드코어 모드">🔴 두음금지</span>`);
    }
    if (rules.manner) {
      badges.push(`<span class="rule-badge rb-manner" title="다음 사람이 이을 수 있는 단어가 남아있는 경우만 허용">🎩 매너모드</span>`);
    }
    if (rules.noOneHit) {
      badges.push(`<span class="rule-badge rb-noonehit" title="사전상 이어질 단어가 없는 절대 한방단어 금지">🛡️ 한방방지</span>`);
    }
    if (rules.mission) {
      badges.push(`<span class="rule-badge rb-mission" title="미션 글자 포함 시 보너스 점수">🎯 미션</span>`);
    }
    if (rules.freeDict) {
      badges.push(`<span class="rule-badge rb-injeong" title="사전에 없는 단어도 모두 허용">✨ 자유단어</span>`);
    }
    return badges.join('');
  }

  function renderRoomsList() {
    const grid = document.getElementById('roomsGrid');
    const allRooms = Array.from(roomsMap.values());

    const filtered = allRooms.filter(r => {
      if (currentRoomFilter === 'WAITING') return r.status === 'WAITING';
      if (currentRoomFilter === 'PLAYING') return r.status === 'PLAYING';
      return true;
    });

    document.getElementById('roomCountBadge').textContent = `${filtered.length}개`;

    if (filtered.length === 0) {
      grid.innerHTML = `
        <div class="empty-rooms">
          <div style="font-size:38px; margin-bottom:10px;">🎮</div>
          <div style="font-size:15px; font-weight:800; margin-bottom:6px;">현재 생성된 방이 없습니다</div>
          <div style="font-size:13px;">우측 상단의 <b>[➕ 방 만들기]</b> 버튼을 눌러 방을 만들어 보세요!</div>
        </div>
      `;
      return;
    }

    grid.innerHTML = filtered.map(room => {
      const isPlaying = room.status === 'PLAYING';
      const lockIcon = room.password ? '🔒 ' : '';
      const stateBadge = isPlaying
        ? `<span class="room-state-pill state-playing">🔥 진행중 (${room.game.currentRound}/${room.totalRounds}R)</span>`
        : `<span class="room-state-pill state-waiting">대기중</span>`;

      const joinDisabled = isPlaying || room.players.length >= room.maxPlayers;

      return `
        <div class="room-card">
          <div>
            <div class="room-card-top">
              <span class="room-id-badge">#${escapeHtml(room.id)}</span>
              <div class="room-title-text">${lockIcon}${escapeHtml(room.title)}</div>
              ${stateBadge}
            </div>
            <div class="room-meta-row" style="margin-top:8px;">
              <span>🎯 <b>${formatGameTypeLabel(room.rules.gameType)}</b></span>
              <span>👥 ${room.players.length}/${room.maxPlayers}명 · 👁️ 관전 ${room.spectators.length}명</span>
            </div>
            <div class="room-meta-row" style="margin-top:4px;">
              <span>⏱️ ${room.totalRounds}라운드 · 라운드당 ${room.roundTime}초</span>
            </div>
          </div>
          <div class="rule-badges-wrap">
            ${buildRuleBadgesHTML(room.rules)}
          </div>
          <div class="room-card-actions">
            <button class="btn ${joinDisabled ? 'btn-outline' : 'btn-primary'} btn-sm" onclick="App.joinRoom('${room.id}', false)" ${joinDisabled ? 'disabled' : ''}>
              🎮 참가하기
            </button>
            <button class="btn btn-outline btn-sm" onclick="App.joinRoom('${room.id}', true)">
              👁️ 관전하기 (${room.spectators.length})
            </button>
          </div>
        </div>
      `;
    }).join('');
  }

  /**
   * 원본 끄투처럼 중앙 전광판 단어의 이어질 음절을 하이라이트하여 반환
   */
  function formatPlayedWordHTML(word, gameType, dueumEnabled) {
    if (!word) return '';
    if (gameType === 'FRONT') {
      const first = word[0];
      const rest = word.slice(1);
      const formattedFirst = Hangul.formatTargetChar(first, dueumEnabled);
      return `<span class="word-tail-highlight">${escapeHtml(formattedFirst)}</span>${escapeHtml(rest)}`;
    }
    const head = word.slice(0, -1);
    const tail = word[word.length - 1];
    const formattedTail = Hangul.formatTargetChar(tail, dueumEnabled);
    return `${escapeHtml(head)}<span class="word-tail-highlight">${escapeHtml(formattedTail)}</span>`;
  }

  /**
   * 오답/규칙 위반 단어 입력 시 원본 끄투처럼 중앙 전광판을 흔들고 1.1초 뒤 원래 제시어로 복원
   */
  function showWordRejectedFeedback(playerId, playerNickname, rawWord, reason) {
    SoundFX.wordError();
    showPlayerSpeechBubble(playerId, `❌ ${rawWord} (${reason})`);

    const liveWordBox = document.getElementById('liveWordBox');
    const meaningBar = document.getElementById('wordMeaningBar');
    if (!liveWordBox || !meaningBar) return;

    if (wordRejectRevertTimeout) {
      clearTimeout(wordRejectRevertTimeout);
    }

    liveWordBox.classList.remove('typing-preview');
    liveWordBox.classList.add('word-error-shake');
    liveWordBox.textContent = `❌ ${rawWord}`;
    meaningBar.innerHTML = `<span class="injeong-tag" style="background:#dc2626;">입력 실패</span> <span>[${escapeHtml(playerNickname)}] ${escapeHtml(reason)}</span>`;

    wordRejectRevertTimeout = setTimeout(() => {
      liveWordBox.classList.remove('word-error-shake');
      if (myUser.roomId && roomsMap.has(myUser.roomId)) {
        const room = roomsMap.get(myUser.roomId);
        restoreCenterWordDisplay(room);
      }
    }, 1150);
  }

  function restoreCenterWordDisplay(room) {
    if (!room) return;
    const isPlaying = room.status === 'PLAYING';
    const latestHist = room.game.history[room.game.history.length - 1];
    const liveWordBox = document.getElementById('liveWordBox');
    const meaningBar = document.getElementById('wordMeaningBar');
    if (!liveWordBox || !meaningBar) return;

    liveWordBox.classList.remove('typing-preview', 'word-error-shake');
    if (isPlaying && latestHist) {
      liveWordBox.innerHTML = formatPlayedWordHTML(latestHist.word, room.rules.gameType, room.rules.dueum);
      const themeObj = DictionaryEngine.INJEONG_THEMES[latestHist.theme];
      const tagHtml = latestHist.isInjeong
        ? `<span class="injeong-tag" style="background:${themeObj ? themeObj.badgeColor : '#9333ea'};">어인정 · ${themeObj ? themeObj.name : '커스텀'}</span>`
        : `<span class="injeong-tag" style="background:#2563eb;">표준 명사</span>`;
      meaningBar.innerHTML = `${tagHtml} <span>${escapeHtml(latestHist.meaning)} (+${latestHist.scoreDelta}점)</span>`;
    } else {
      liveWordBox.textContent = isPlaying ? `${Hangul.formatTargetChar(room.game.targetChar, room.rules.dueum)}` : 'KKuTu LITE';
      meaningBar.innerHTML = `<span>${escapeHtml(room.game.lastBanner)}</span>`;
    }
  }

  /**
   * 게임 방(Room Arena) 전체 화면 렌더링
   */
  function renderRoomArena() {
    if (!myUser.roomId) return;
    const room = roomsMap.get(myUser.roomId);
    if (!room) return;

    const isHost = room.hostId === myUser.id;
    const isPlaying = room.status === 'PLAYING';

    // 1) 상단 방 정보 헤더
    document.getElementById('roomHeaderTitle').textContent = `#${room.id} ${room.title}`;
    document.getElementById('roomHeaderMode').textContent = `${formatGameTypeLabel(room.rules.gameType)} · ${room.totalRounds}R · ${room.roundTime}초`;
    document.getElementById('roomHeaderRuleBadges').innerHTML = buildRuleBadgesHTML(room.rules);

    // 방장 전용 버튼 표시/숨김
    const hostControls = document.getElementById('hostOnlyControls');
    if (isHost && !isPlaying) {
      hostControls.classList.remove('hidden');
    } else {
      hostControls.classList.add('hidden');
    }

    // 관전 전환 버튼
    const specBtn = document.getElementById('btnToggleSpectate');
    specBtn.textContent = myUser.isSpectator ? '🎮 참가 전환' : '👁️ 관전 전환';
    specBtn.disabled = isPlaying;

    // 시작 / 준비 버튼
    const startBtn = document.getElementById('btnReadyOrStart');
    if (myUser.isSpectator) {
      startBtn.textContent = '👁️ 관전 중';
      startBtn.disabled = true;
      startBtn.className = 'btn btn-outline btn-sm';
    } else if (isHost) {
      startBtn.textContent = isPlaying ? '🔥 진행 중' : '🚀 게임 시작';
      startBtn.disabled = isPlaying;
      startBtn.className = 'btn btn-success btn-sm';
    } else {
      const mePlayer = room.players.find(p => p.id === myUser.id);
      const isReady = mePlayer ? mePlayer.ready : false;
      startBtn.textContent = isReady ? '✅ 준비 완료' : '⚡ 준비하기';
      startBtn.disabled = isPlaying;
      startBtn.className = isReady ? 'btn btn-warning btn-sm' : 'btn btn-primary btn-sm';
    }

    // 2) 관전자 스트립
    const specBar = document.getElementById('spectatorStrip');
    const specNames = room.spectators.map(s => `${s.avatar || '👁️'} ${escapeHtml(s.nickname)}`).join(', ');
    document.getElementById('spectatorListText').innerHTML = room.spectators.length > 0
      ? `👁️ <b>관전 중 (${room.spectators.length}명):</b> ${specNames}`
      : `👁️ 현재 관전 중인 유저가 없습니다.`;
    document.getElementById('mySpectatorBadge').textContent = myUser.isSpectator
      ? '관전자 모드로 시청 중'
      : '';
    specBar.style.display = 'flex';

    // 3) 중앙 끄투 전광판 (Arena Board) + 원본 끄투 상단 라운드 제시어 글자 블록
    document.getElementById('arenaRoundText').textContent = `ROUND ${room.game.currentRound} / ${room.totalRounds}`;
    document.getElementById('arenaChainBadge').textContent = `${room.game.chainCount} CHAIN`;

    const titleStrip = document.getElementById('roundTitleStrip');
    if (titleStrip) {
      const titleWord = room.game.roundTitleWord || '';
      if (isPlaying && titleWord) {
        titleStrip.innerHTML = titleWord.split('').map((ch, idx) => {
          const rNum = idx + 1;
          const cls = rNum === room.game.currentRound ? 'active' : rNum < room.game.currentRound ? 'done' : '';
          return `<span class="round-char-box ${cls}">${escapeHtml(ch)}</span>`;
        }).join('');
      } else {
        titleStrip.innerHTML = '';
      }
    }

    // 히스토리 단어 체인 스트립
    const histStrip = document.getElementById('wordHistoryStrip');
    if (room.game.history.length === 0) {
      histStrip.innerHTML = `<span style="font-size:12px; opacity:0.75;">이번 라운드에 입력된 단어가 체인으로 표시됩니다.</span>`;
    } else {
      const recent = room.game.history.slice(-8);
      histStrip.innerHTML = recent.map((h, idx) => {
        const isLatest = idx === recent.length - 1;
        return `<span class="history-chip ${isLatest ? 'latest' : ''}">${escapeHtml(h.word)} <small style="opacity:0.8;">+${h.scoreDelta}</small></span>`;
      }).join('<span style="opacity:0.6;">➔</span>');
    }

    // 제시 글자 & 두음법칙 표시 & 남은 연결 가능 단어 수
    const targetMainEl = document.getElementById('targetCharMain');
    const targetSubEl = document.getElementById('targetSubInfo');
    if (isPlaying && room.game.targetChar) {
      targetMainEl.textContent = Hangul.formatTargetChar(room.game.targetChar, room.rules.dueum);
      const usedSet = new Set(room.game.usedWords);
      const remainCount = DictionaryEngine.getFollowUpWords(room.game.targetChar, room.rules, usedSet).length;
      targetSubEl.textContent = `연결 가능: ${remainCount.toLocaleString()}개`;
    } else {
      targetMainEl.textContent = '대기중';
      targetSubEl.textContent = room.rules.dueum ? '두음법칙 ON' : '두음법칙 OFF';
    }

    // 중앙 단어/뜻 보드
    const activePlayer = isPlaying ? room.players[room.game.turnIndex % room.players.length] : null;
    document.getElementById('turnOwnerBanner').textContent = isPlaying && activePlayer
      ? `🎯 현재 차례: ${activePlayer.avatar} ${activePlayer.nickname}${activePlayer.id === myUser.id ? ' (내 차례!)' : ''}`
      : room.game.lastBanner;

    restoreCenterWordDisplay(room);

    // 미션 글자 박스
    const missionCharEl = document.getElementById('missionCharDisplay');
    if (room.rules.mission) {
      missionCharEl.textContent = isPlaying && room.game.missionChar ? room.game.missionChar : 'ON';
    } else {
      missionCharEl.textContent = 'OFF';
    }

    // 타이머 바
    updateTimerBarsDOM(room);

    // 4) 플레이어 카드 슬롯
    const playersGrid = document.getElementById('playersSlotGrid');
    playersGrid.innerHTML = room.players.map((p, idx) => {
      const isTurn = isPlaying && (room.game.turnIndex % room.players.length) === idx;
      const isMe = p.id === myUser.id;
      const crown = p.id === room.hostId ? '👑 ' : '';
      let statusTag = '';
      if (isPlaying) {
        statusTag = isTurn
          ? `<span class="player-status-tag tag-turn">🎯 입력 차례</span>`
          : `<span class="player-status-tag tag-wait">${escapeHtml(p.lastWord || '대기')}</span>`;
      } else {
        statusTag = (p.ready || p.id === room.hostId)
          ? `<span class="player-status-tag tag-ready">READY</span>`
          : `<span class="player-status-tag tag-wait">대기중</span>`;
      }

      return `
        <div class="player-card ${isTurn ? 'active-turn' : ''} ${isMe ? 'is-me' : ''}" id="pcard_${p.id}">
          <div class="player-avatar">${escapeHtml(p.avatar || '🦊')}</div>
          <div class="player-name-row">
            <span>${crown}${escapeHtml(p.nickname)}${isMe ? ' (나)' : ''}</span>
          </div>
          <div class="player-score">${p.score.toLocaleString()}점</div>
          ${statusTag}
        </div>
      `;
    }).join('');

    // 5) 전광판 전용 끝말잇기 단어 입력창 상태 업데이트
    updateRoomInputBarState();
  }

  function updateTimerBarsDOM(room) {
    if (!room || !room.game) return;
    const turnPct = Math.max(0, Math.min(100, (room.game.turnTimeLeft / Math.max(0.1, room.game.turnTimeMax)) * 100));
    const roundPct = Math.max(0, Math.min(100, (room.game.roundTimeLeft / Math.max(0.1, room.game.roundTimeMax)) * 100));

    const turnFill = document.getElementById('turnTimerFill');
    const roundFill = document.getElementById('roundTimerFill');
    if (turnFill) {
      turnFill.style.width = `${turnPct}%`;
      turnFill.className = 'timer-fill turn-timer-fill' + (turnPct < 25 ? ' danger' : turnPct < 55 ? ' warning' : '');
    }
    if (roundFill) {
      roundFill.style.width = `${roundPct}%`;
    }
    const turnVal = document.getElementById('turnTimerVal');
    const roundVal = document.getElementById('roundTimerVal');
    if (turnVal) turnVal.textContent = `${room.game.turnTimeLeft.toFixed(1)}s`;
    if (roundVal) roundVal.textContent = `${room.game.roundTimeLeft.toFixed(1)}s`;
  }

  function updateLiveTypingDisplay(playerId, text) {
    const liveWordBox = document.getElementById('liveWordBox');
    if (!liveWordBox) return;
    if (!text) {
      if (myUser.roomId && roomsMap.has(myUser.roomId)) {
        restoreCenterWordDisplay(roomsMap.get(myUser.roomId));
      }
      return;
    }
    liveWordBox.classList.remove('word-error-shake');
    liveWordBox.classList.add('typing-preview');
    liveWordBox.textContent = text;
  }

  function updateRoomInputBarState() {
    if (!myUser.roomId) return;
    const room = roomsMap.get(myUser.roomId);
    if (!room) return;

    const wrap = document.getElementById('arenaWordInputWrap');
    const prefix = document.getElementById('arenaWordPrefix');
    const wordInput = document.getElementById('arenaWordInput');
    const wordBtn = document.getElementById('btnArenaWordSubmit');
    const chatTag = document.getElementById('chatRoleTag');

    const activePlayer = room.status === 'PLAYING'
      ? room.players[room.game.turnIndex % room.players.length]
      : null;
    const isMyTurn = Boolean(activePlayer && activePlayer.id === myUser.id && !myUser.isSpectator);
    const currentTurnKey = `${room.id}_${room.status}_${room.game?.currentRound}_${room.game?.chainCount}_${room.game?.turnIndex}`;

    if (chatTag) {
      chatTag.textContent = myUser.isSpectator ? '👁️ 관전 채팅' : '💬 일반 채팅';
    }

    if (isMyTurn) {
      wrap.classList.add('my-turn-active');
      const formatted = Hangul.formatTargetChar(room.game.targetChar, room.rules.dueum);
      prefix.textContent = `🎯 내 차례! [${formatted}]`;
      wordInput.disabled = false;
      wordBtn.disabled = false;
      wordInput.placeholder = `'${formatted}'(으)로 시작하는 단어를 입력하고 Enter를 누르세요!`;

      // 내 턴으로 방금 전환되었을 때 알림음 + 입력창 자동 포커스 (비방장 참가자 포함!)
      if (lastTurnFocusKey !== currentTurnKey) {
        lastTurnFocusKey = currentTurnKey;
        SoundFX.turnStart();
        wordInput.value = '';
        wordInput.focus();
      }
    } else {
      lastTurnFocusKey = currentTurnKey;
      wrap.classList.remove('my-turn-active');
      prefix.textContent = room.status === 'PLAYING' && activePlayer
        ? `⏳ ${activePlayer.nickname}님 차례`
        : '🎯 끝말잇기 단어 입력';
      wordInput.disabled = false;
      wordBtn.disabled = true;
      wordInput.placeholder = room.status === 'PLAYING'
        ? `현재 ${activePlayer ? activePlayer.nickname : '다른 플레이어'}님의 차례입니다 (내 차례가 되면 여기에 단어를 입력합니다)`
        : '게임이 시작되고 내 차례가 되면 여기에 단어를 입력합니다!';
    }
  }

  // 플레이어 캐릭터 카드 위 말풍선 표시
  function showPlayerSpeechBubble(playerId, text) {
    const card = document.getElementById(`pcard_${playerId}`);
    if (!card) return;
    const existing = card.querySelector('.speech-bubble');
    if (existing) existing.remove();

    const bubble = document.createElement('div');
    bubble.className = 'speech-bubble';
    bubble.textContent = text;
    card.appendChild(bubble);

    setTimeout(() => {
      if (bubble.parentNode) bubble.remove();
    }, 3200);
  }

  // ==========================================
  // 8. 채팅 & 모달 헬퍼
  // ==========================================
  function sendLobbyChat() {
    const input = document.getElementById('lobbyChatInput');
    const text = input.value.trim();
    if (!text) return;
    input.value = '';
    appendLobbyChatLine(myUser.nickname, text);
    broadcastPacket({
      type: 'LOBBY_CHAT',
      senderName: myUser.nickname,
      text
    });
  }

  function appendLobbyChatLine(sender, text) {
    const box = document.getElementById('lobbyChatMessages');
    const div = document.createElement('div');
    div.className = 'chat-line';
    div.innerHTML = `<span class="chat-sender">${escapeHtml(sender)}:</span><span>${escapeHtml(text)}</span>`;
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
  }

  function addLobbySystemChat(text) {
    const box = document.getElementById('lobbyChatMessages');
    const div = document.createElement('div');
    div.className = 'chat-line sys-msg';
    div.textContent = text;
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
  }

  function clearRoomChatUI() {
    document.getElementById('roomChatMessages').innerHTML = '';
  }

  function appendRoomChatLine(sender, text, isSpectator = false, kind = '') {
    const box = document.getElementById('roomChatMessages');
    const div = document.createElement('div');
    if (kind) {
      div.className = `chat-line ${kind}`;
      div.textContent = text;
    } else {
      div.className = 'chat-line';
      const specLabel = isSpectator ? ' [관전]' : '';
      div.innerHTML = `<span class="chat-sender ${isSpectator ? 'spectator' : ''}">${escapeHtml(sender)}${specLabel}:</span><span>${escapeHtml(text)}</span>`;
    }
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
  }

  function sendRoomSystemChat(roomId, text, kind = 'sys-msg') {
    if (myUser.roomId === roomId) {
      appendRoomChatLine('', text, false, kind);
    }
    broadcastPacket({
      type: 'ROOM_CHAT',
      roomId,
      senderName: '',
      text,
      kind
    });
  }

  // 방 설정 변경 모달 열기
  function openEditRoomModal() {
    if (!myUser.roomId) return;
    const room = roomsMap.get(myUser.roomId);
    if (!room || room.hostId !== myUser.id || room.status === 'PLAYING') return;

    editingRoomMode = true;
    document.getElementById('createRoomModalTitle').textContent = '⚙️ 방 규칙 및 설정 변경';
    document.getElementById('btnConfirmCreateRoom').textContent = '설정 저장하기';

    document.getElementById('roomTitleInput').value = room.title;
    document.getElementById('roomPwInput').value = room.password || '';
    document.getElementById('roomMaxPlayers').value = String(room.maxPlayers);
    document.getElementById('roomRounds').value = String(room.totalRounds);
    document.getElementById('roomRoundTime').value = String(room.roundTime);
    document.getElementById('roomGameType').value = room.rules.gameType || 'KR_STD';

    document.getElementById('ruleInjeong').checked = Boolean(room.rules.injeong);
    document.getElementById('ruleDueum').checked = room.rules.dueum !== false;
    document.getElementById('ruleManner').checked = Boolean(room.rules.manner);
    document.getElementById('ruleNoOneHit').checked = Boolean(room.rules.noOneHit);
    document.getElementById('ruleMission').checked = Boolean(room.rules.mission);
    document.getElementById('ruleFreeDict').checked = Boolean(room.rules.freeDict);

    openModal('createRoomModal');
  }

  // 프로필 변경 모달
  function openProfileModal() {
    document.getElementById('profileNickInput').value = myUser.nickname;
    const avatarWrap = document.getElementById('avatarPickerWrap');
    avatarWrap.innerHTML = AVATARS.map(av => `
      <button type="button" class="btn ${av === myUser.avatar ? 'btn-primary' : 'btn-outline'}" style="font-size:20px; padding:6px 10px;" onclick="App.selectAvatar('${av}')">${av}</button>
    `).join('');
    openModal('profileModal');
  }

  function selectAvatar(av) {
    myUser.avatar = av;
    openProfileModal();
  }

  function saveProfileFromModal() {
    const newNick = document.getElementById('profileNickInput').value.trim();
    if (newNick.length >= 2 && newNick.length <= 12) {
      myUser.nickname = newNick;
    }
    saveProfile();
    renderProfileHeader();
    usersMap.set(myUser.id, { ...myUser });
    renderLobbyUsers();
    closeModal('profileModal');
    showToast('프로필이 저장되었습니다.');
  }

  // 단어장 검색 및 커스텀 어인정 추가
  function updateDictStatsUI() {
    const stats = DictionaryEngine.getStats();
    const el = document.getElementById('dictStatsSummary');
    if (el) {
      el.textContent = `총 ${stats.total.toLocaleString()}개 단어 (표준 ${stats.standardCount.toLocaleString()}개 · 어인정 ${stats.injeongCount.toLocaleString()}개 · 커스텀 ${stats.customCount}개)`;
    }
  }

  function renderDictionarySearchList() {
    const query = document.getElementById('dictSearchInput').value;
    const filter = document.getElementById('dictFilterSelect').value;
    const list = DictionaryEngine.searchDictionary(query, filter, { injeong: true, dueum: true });
    const box = document.getElementById('dictSearchResultBox');

    if (list.length === 0) {
      box.innerHTML = `<div style="padding:24px; text-align:center; color:#94a3b8;">조건에 맞는 단어가 없습니다. 위 입력창에서 새 단어로 바로 추가해 보세요!</div>`;
      return;
    }

    box.innerHTML = list.slice(0, 120).map(item => {
      const themeObj = DictionaryEngine.INJEONG_THEMES[item.theme];
      const typeTag = item.isInjeong
        ? `<span class="rule-badge rb-injeong">${themeObj ? themeObj.name : '어인정'}</span>`
        : `<span class="rule-badge rb-dueum">표준</span>`;
      const oneHitTag = item.oneHit
        ? `<span class="rule-badge rb-dueum-off">💀 한방단어 (후속 0개)</span>`
        : `<span class="rule-badge rb-manner">후속 ${item.followCount}개</span>`;
      const delBtn = item.isCustom
        ? `<button class="btn btn-danger btn-sm" onclick="App.deleteCustomWordUI('${escapeHtml(item.word)}')">삭제</button>`
        : '';

      return `
        <div class="dict-item">
          <div>
            <b style="font-size:14px; color:#fff; margin-right:6px;">${escapeHtml(item.word)}</b>
            ${typeTag} ${oneHitTag}
            <div style="font-size:12px; color:#94a3b8; margin-top:2px;">${escapeHtml(item.meaning)}</div>
          </div>
          <div>${delBtn}</div>
        </div>
      `;
    }).join('');
  }

  function handleAddCustomWordUI() {
    const word = document.getElementById('newWordInput').value.trim();
    const meaning = document.getElementById('newWordMeaningInput').value.trim();
    const typeVal = document.getElementById('newWordTypeSelect').value;
    const isInjeong = typeVal !== 'STANDARD';
    const theme = isInjeong ? typeVal : 'STANDARD';

    const res = DictionaryEngine.addCustomWord(word, meaning, isInjeong, theme);
    if (!res.ok) {
      showToast('❌ ' + res.reason);
      return;
    }

    document.getElementById('newWordInput').value = '';
    document.getElementById('newWordMeaningInput').value = '';
    updateDictStatsUI();
    renderDictionarySearchList();
    showToast(`✅ '${res.entry.word}' 단어가 사전에 추가되었습니다! (모든 참가자와 자동 공유)`);

    broadcastPacket({
      type: 'CUSTOM_WORD_ADDED',
      entry: res.entry
    });
  }

  function deleteCustomWordUI(word) {
    if (DictionaryEngine.removeCustomWord(word)) {
      updateDictStatsUI();
      renderDictionarySearchList();
      showToast(`🗑️ '${word}' 단어가 삭제되었습니다.`);
    }
  }

  function showGameResultModal(sortedPlayers) {
    const body = document.getElementById('gameResultModalBody');
    body.innerHTML = sortedPlayers.map((p, idx) => {
      const medal = idx === 0 ? '🥇 1위' : idx === 1 ? '🥈 2위' : idx === 2 ? '🥉 3위' : `${idx + 1}위`;
      return `
        <div class="user-item" style="padding:12px 16px; font-size:15px;">
          <div class="user-item-left">
            <span style="font-weight:900; color:#fbbf24; width:56px;">${medal}</span>
            <span style="font-size:22px;">${escapeHtml(p.avatar)}</span>
            <b>${escapeHtml(p.nickname)}</b>
          </div>
          <div style="font-weight:900; color:#38bdf8;">${p.score.toLocaleString()}점</div>
        </div>
      `;
    }).join('');
    openModal('gameResultModal');
  }

  function openModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove('hidden');
  }

  function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('hidden');
  }

  function showToast(msg) {
    const wrap = document.getElementById('toastContainer');
    const div = document.createElement('div');
    div.className = 'toast';
    div.textContent = msg;
    wrap.appendChild(div);
    setTimeout(() => {
      if (div.parentNode) div.remove();
    }, 3400);
  }

  function escapeHtml(str) {
    return String(str || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  return {
    init,
    joinRoom,
    selectAvatar,
    deleteCustomWordUI
  };
})();

window.addEventListener('DOMContentLoaded', () => {
  App.init();
});
