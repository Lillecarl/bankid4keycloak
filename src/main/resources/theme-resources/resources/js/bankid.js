'use strict';

/* For the start form */
function validateForm() {
	let nin = document.getElementById('nin');
	let valid = nin !== null && /^(19|20)[0-9]{10}$/.test(nin.value);
	document.getElementById('error').style.display = valid ? 'none' : 'inline';
	return valid;
}

/*
 * For the login page: polls the order, draws the QR code once a second, and
 * shows the time limit with a countdown and an extend button, as BankID's
 * accessibility guidance asks.
 */
function startBankidLogin(spinnerOptions) {
	const root = document.getElementById('bankid');
	const query = 'state=' + encodeURIComponent(root.dataset.state);
	// The BankID app returns to this page with #nonce=... after a same-device
	// order; collect checks it against the session.
	const returned = /(?:^#|&)nonce=([^&]+)/.exec(window.location.hash);
	const collectQuery = returned === null ? query : query + '&nonce=' + encodeURIComponent(returned[1]);
	if (returned !== null) {
		history.replaceState(null, '', window.location.pathname + window.location.search);
	}
	const qrcode = document.getElementById('qrcode');
	const qrButton = document.getElementById('qrcode-button');
	const qrcodeImg = document.getElementById('qrcode-img');
	const progress = document.getElementById('bankid-progress');
	const countdown = document.getElementById('bankid-countdown');
	const announce = document.getElementById('bankid-announce');
	const extendButton = document.getElementById('bankid-extend');
	const expired = document.getElementById('bankid-expired');
	let frames = null;
	let deadline = null;
	let ticker = null;
	let lastStep = null;
	let polling = true;

	function frame() {
		qrcodeImg.src = 'qrcode?' + query + '&t=' + Date.now();
	}

	function stopFrames() {
		if (frames !== null) {
			clearInterval(frames);
			frames = null;
		}
	}

	function stopTimer() {
		if (ticker !== null) {
			clearInterval(ticker);
			ticker = null;
		}
		document.getElementById('bankid-timer').hidden = true;
	}

	function setFullScreen(on) {
		if (qrButton !== null) {
			qrButton.setAttribute('aria-pressed', on ? 'true' : 'false');
		}
	}

	// Screen readers hear the time only at these steps: 5 to 1 minutes, then
	// 50 to 10 seconds.
	function step(seconds) {
		if (seconds > 60) {
			const minutes = Math.ceil(seconds / 60);
			return (minutes === 1 ? announce.dataset.minute : announce.dataset.minutes).replace('{0}', minutes);
		}
		const tens = Math.ceil(seconds / 10) * 10;
		return tens >= 60 ? announce.dataset.minute.replace('{0}', 1) : announce.dataset.seconds.replace('{0}', tens);
	}

	function tick() {
		const seconds = Math.max(0, Math.round((deadline - Date.now()) / 1000));
		progress.value = seconds;
		countdown.textContent = Math.floor(seconds / 60) + ':' + String(seconds % 60).padStart(2, '0');
		const text = step(seconds);
		if (text !== lastStep && seconds > 0) {
			lastStep = text;
			announce.textContent = text;
		}
		extendButton.hidden = seconds > 30;
	}

	function setRemaining(seconds) {
		if (typeof seconds !== 'number' || seconds <= 0) {
			return;
		}
		deadline = Date.now() + seconds * 1000;
		if (ticker === null) {
			ticker = setInterval(tick, 1000);
		}
		tick();
	}

	function showExpired() {
		polling = false;
		stopFrames();
		setFullScreen(false);
		if (qrcode !== null) {
			qrcode.style.display = 'none';
		}
		if (ticker !== null) {
			clearInterval(ticker);
			ticker = null;
		}
		progress.hidden = true;
		countdown.hidden = true;
		extendButton.hidden = true;
		expired.hidden = false;
		document.getElementById('bankid-restart').focus();
	}

	function redirectToError(hintCode) {
		polling = false;
		stopFrames();
		window.location.href = 'error?code=' + encodeURIComponent(hintCode || '') + '&' + query;
	}

	function showProgress() {
		stopFrames();
		stopTimer();
		setFullScreen(false);
		if (qrcode !== null) {
			qrcode.style.display = 'none';
		}
		const loading = document.getElementById('loading');
		if (loading.style.display !== 'flex') {
			loading.style.display = 'flex';
			new Spin.Spinner(spinnerOptions).spin(document.getElementById('progress-loader'));
		}
	}

	async function extend() {
		if (extendButton.hidden) {
			return;
		}
		let answer;
		try {
			const response = await fetch('extend?' + query, { method: 'POST', cache: 'no-store' });
			answer = await response.json();
		} catch (e) {
			return;
		}
		if (answer.status !== 'pending') {
			redirectToError(answer.hintCode);
			return;
		}
		lastStep = null;
		setRemaining(answer.remaining);
		if (qrButton !== null) {
			qrButton.focus();
		}
	}

	async function poll() {
		if (!polling) {
			return;
		}
		let answer;
		try {
			const response = await fetch('collect?' + collectQuery, { cache: 'no-store' });
			answer = await response.json();
		} catch (e) {
			setTimeout(poll, 2000);
			return;
		}
		if (answer.status === 'complete') {
			polling = false;
			stopFrames();
			window.location.href = 'done?' + query;
		} else if (answer.status === 'pending') {
			if (answer.hintCode === 'outstandingTransaction' || answer.hintCode === 'noClient') {
				setRemaining(answer.remaining);
			} else {
				showProgress();
			}
			setTimeout(poll, 2000);
		} else if (answer.status === 'expired') {
			showExpired();
		} else {
			redirectToError(answer.hintCode);
		}
	}

	if (qrButton !== null) {
		qrButton.addEventListener('click', function () {
			setFullScreen(qrButton.getAttribute('aria-pressed') !== 'true');
		});
	}
	document.addEventListener('keydown', function (event) {
		if (event.key === 'Escape') {
			setFullScreen(false);
		} else if (event.key === ' ' && !extendButton.hidden && document.activeElement !== extendButton) {
			// BankID's guidance: Space extends the time limit wherever the focus is.
			event.preventDefault();
			extend();
		}
	});
	extendButton.addEventListener('click', extend);

	if (qrcodeImg !== null) {
		frame();
		frames = setInterval(frame, 1000);
	}
	poll();
}
