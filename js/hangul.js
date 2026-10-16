/**
 * KKuTu-Lite Hangul & Dueum Law (두음법칙) Engine + Retro Audio Synthesizer
 */

const Hangul = (() => {
  const HANGUL_BASE = 0xAC00;
  const HANGUL_END = 0xD7A3;

  const CHOSEONG = [
    'ㄱ', 'ㄲ', 'ㄴ', 'ㄷ', 'ㄸ', 'ㄹ', 'ㅁ', 'ㅂ', 'ㅃ',
    'ㅅ', 'ㅆ', 'ㅇ', 'ㅈ', 'ㅉ', 'ㅊ', 'ㅋ', 'ㅌ', 'ㅍ', 'ㅎ'
  ];

  const JUNGSEONG = [
    'ㅏ', 'ㅐ', 'ㅑ', 'ㅒ', 'ㅓ', 'ㅔ', 'ㅕ', 'ㅖ', 'ㅗ', 'ㅘ', 'ㅙ',
    'ㅚ', 'ㅛ', 'ㅜ', 'ㅝ', 'ㅞ', 'ㅟ', 'ㅠ', 'ㅡ', 'ㅢ', 'ㅣ'
  ];

  const JONGSEONG = [
    '', 'ㄱ', 'ㄲ', 'ㄳ', 'ㄴ', 'ㄵ', 'ㄶ', 'ㄷ', 'ㄹ', 'ㄺ', 'ㄻ',
    'ㄼ', 'ㄽ', 'ㄾ', 'ㄿ', 'ㅀ', 'ㅁ', 'ㅂ', 'ㅄ', 'ㅅ', 'ㅆ', 'ㅇ',
    'ㅈ', 'ㅊ', 'ㅋ', 'ㅌ', 'ㅍ', 'ㅎ'
  ];

  function isHangulSyllable(ch) {
    if (!ch || ch.length !== 1) return false;
    const code = ch.charCodeAt(0);
    return code >= HANGUL_BASE && code <= HANGUL_END;
  }

  function isHangulWord(word) {
    if (!word || typeof word !== 'string') return false;
    for (let i = 0; i < word.length; i++) {
      if (!isHangulSyllable(word[i])) return false;
    }
    return true;
  }

  function decompose(ch) {
    if (!isHangulSyllable(ch)) return null;
    const code = ch.charCodeAt(0) - HANGUL_BASE;
    const jong = code % 28;
    const jung = ((code - jong) / 28) % 21;
    const cho = Math.floor((code - jong) / 28 / 21);
    return {
      cho,
      jung,
      jong,
      choChar: CHOSEONG[cho],
      jungChar: JUNGSEONG[jung],
      jongChar: JONGSEONG[jong]
    };
  }

  function compose(cho, jung, jong = 0) {
    const code = HANGUL_BASE + (cho * 21 + jung) * 28 + jong;
    return String.fromCharCode(code);
  }

  /**
   * 한국어 두음법칙 변환 함수 (원본 끄투 규격)
   * 1) ㄴ + (ㅣ, ㅑ, ㅕ, ㅛ, ㅠ, ㅖ, ㅒ) -> ㅇ
   * 2) ㄹ + (ㅣ, ㅑ, ㅕ, ㅖ, ㅛ, ㅠ, ㅒ) -> ㅇ
   * 3) ㄹ + (ㅏ, ㅐ, ㅗ, ㅚ, ㅜ, ㅡ) -> ㄴ
   * @param {string} ch 한 글자 음절
   * @returns {string|null} 변환된 음절 (두음법칙 대상이 아니면 null)
   */
  function getDueum(ch) {
    const d = decompose(ch);
    if (!d) return null;

    // 중성 인덱스:
    // ㅏ(0), ㅐ(1), ㅑ(2), ㅒ(3), ㅓ(4), ㅔ(5), ㅕ(6), ㅖ(7), ㅗ(8),
    // ㅘ(9), ㅙ(10), ㅚ(11), ㅛ(12), ㅜ(13), ㅝ(14), ㅞ(15), ㅟ(16), ㅠ(17), ㅡ(18), ㅢ(19), ㅣ(20)
    const yVowels = [2, 3, 6, 7, 12, 17, 20]; // ㅑ, ㅒ, ㅕ, ㅖ, ㅛ, ㅠ, ㅣ
    const nVowels = [0, 1, 8, 11, 13, 18];    // ㅏ, ㅐ, ㅗ, ㅚ, ㅜ, ㅡ

    // 1. 초성이 'ㄴ'(2)이고 중성이 yVowels에 해당하면 초성을 'ㅇ'(11)으로 변환
    if (d.cho === 2 && yVowels.includes(d.jung)) {
      return compose(11, d.jung, d.jong);
    }

    // 2. 초성이 'ㄹ'(5)일 때
    if (d.cho === 5) {
      if (yVowels.includes(d.jung)) {
        // 랴, 려, 례, 료, 류, 리 등 -> 야, 여, 예, 요, 유, 이
        return compose(11, d.jung, d.jong);
      }
      if (nVowels.includes(d.jung)) {
        // 라, 래, 로, 뢰, 루, 르 등 -> 나, 내, 노, 뇌, 누, 느
        return compose(2, d.jung, d.jong);
      }
    }

    return null;
  }

  /**
   * 특정 음절에서 허용되는 시작 음절 배열을 반환
   * @param {string} ch 기준 음절
   * @param {boolean} allowDueum 두음법칙 허용 여부
   * @returns {string[]} 허용 음절 목록 (예: ['름', '늠'] 또는 ['량', '양'])
   */
  function getValidStartChars(ch, allowDueum = true) {
    if (!ch) return [];
    const list = [ch];
    if (allowDueum) {
      const dueum = getDueum(ch);
      if (dueum && dueum !== ch) {
        list.push(dueum);
      }
    }
    return list;
  }

  /**
   * 표시용 문자열 생성: 예) '름' -> '름 (늠)'
   */
  function formatTargetChar(ch, allowDueum = true) {
    const chars = getValidStartChars(ch, allowDueum);
    if (chars.length > 1) {
      return `${chars[0]} (${chars[1]})`;
    }
    return chars[0] || '';
  }

  function getChoseongString(word) {
    if (!word) return '';
    return Array.from(word).map(ch => {
      const d = decompose(ch);
      return d ? d.choChar : ch;
    }).join('');
  }

  return {
    isHangulSyllable,
    isHangulWord,
    decompose,
    compose,
    getDueum,
    getValidStartChars,
    formatTargetChar,
    getChoseongString
  };
})();

/**
 * Web Audio API 기반 끄투 스타일 효과음 신디사이저 (외부 오디오 파일 불필요)
 */
const SoundFX = (() => {
  let ctx = null;
  let muted = false;

  function getCtx() {
    if (muted) return null;
    if (!ctx) {
      const AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx) ctx = new AudioCtx();
    }
    if (ctx && ctx.state === 'suspended') {
      ctx.resume().catch(() => {});
    }
    return ctx;
  }

  function playTone(freq, type = 'sine', duration = 0.12, gainVal = 0.12, delay = 0) {
    const c = getCtx();
    if (!c) return;
    const now = c.currentTime + delay;
    const osc = c.createOscillator();
    const gain = c.createGain();
    osc.type = type;
    osc.frequency.setValueAtTime(freq, now);
    gain.gain.setValueAtTime(gainVal, now);
    gain.gain.exponentialRampToValueAtTime(0.001, now + duration);
    osc.connect(gain);
    gain.connect(c.destination);
    osc.start(now);
    osc.stop(now + duration);
  }

  return {
    isMuted: () => muted,
    toggleMute: () => {
      muted = !muted;
      return muted;
    },
    // 단어 성공 효과음 (경쾌한 상승 화음)
    wordSuccess: (isMission = false) => {
      if (isMission) {
        playTone(523.25, 'triangle', 0.12, 0.16, 0);     // C5
        playTone(659.25, 'triangle', 0.12, 0.16, 0.06);  // E5
        playTone(783.99, 'triangle', 0.14, 0.16, 0.12);  // G5
        playTone(1046.50, 'sine', 0.25, 0.20, 0.18);     // C6
      } else {
        playTone(440, 'triangle', 0.10, 0.14, 0);        // A4
        playTone(554.37, 'triangle', 0.12, 0.14, 0.06);  // C#5
        playTone(659.25, 'triangle', 0.16, 0.14, 0.12);  // E5
      }
    },
    // 단어 실패 / 규칙 위반 효과음 (낮은 버저음)
    wordError: () => {
      playTone(190, 'sawtooth', 0.14, 0.12, 0);
      playTone(145, 'sawtooth', 0.20, 0.14, 0.1);
    },
    // 내 턴 시작 알림음
    turnStart: () => {
      playTone(587.33, 'sine', 0.09, 0.12, 0);    // D5
      playTone(880.00, 'sine', 0.14, 0.12, 0.07); // A5
    },
    // 타이머 임박 틱
    tick: (urgent = false) => {
      playTone(urgent ? 960 : 720, 'square', 0.04, urgent ? 0.08 : 0.04, 0);
    },
    // 라운드 종료 (타임아웃 폭탄)
    roundFail: () => {
      playTone(300, 'sawtooth', 0.15, 0.16, 0);
      playTone(220, 'sawtooth', 0.15, 0.16, 0.12);
      playTone(130, 'sawtooth', 0.35, 0.18, 0.24);
    },
    // 게임 시작 팡파레
    gameStart: () => {
      playTone(523.25, 'triangle', 0.12, 0.15, 0);
      playTone(659.25, 'triangle', 0.12, 0.15, 0.10);
      playTone(783.99, 'triangle', 0.12, 0.15, 0.20);
      playTone(1046.50, 'triangle', 0.30, 0.18, 0.30);
    },
    // 게임 승리 팡파레
    gameWin: () => {
      const notes = [523.25, 659.25, 783.99, 1046.5, 783.99, 1046.5];
      const delays = [0, 0.1, 0.2, 0.3, 0.45, 0.58];
      notes.forEach((n, idx) => playTone(n, 'triangle', 0.22, 0.16, delays[idx]));
    }
  };
})();
