'use strict';

/* For the start form */
function validateForm() {
	let nin = document.getElementById('nin');
	let valid = nin !== null && /^(19|20)[0-9]{10}$/.test(nin.value);
	document.getElementById('error').style.display = valid ? 'none' : 'inline';
	return valid;
}

/* For the login page: polls the order, and draws the QR code once a second. */
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
	const qrcodeImg = document.getElementById('qrcode-img');
	let frames = null;

	function frame() {
		qrcodeImg.src = 'qrcode?' + query + '&t=' + Date.now();
	}

	function stopFrames() {
		if (frames !== null) {
			clearInterval(frames);
			frames = null;
		}
	}

	function redirectToError(hintCode) {
		stopFrames();
		window.location.href = 'error?code=' + encodeURIComponent(hintCode || '') + '&' + query;
	}

	function showProgress() {
		stopFrames();
		if (qrcode !== null) {
			qrcode.style.display = 'none';
		}
		const loading = document.getElementById('loading');
		if (loading.style.display !== 'flex') {
			loading.style.display = 'flex';
			new Spin.Spinner(spinnerOptions).spin(document.getElementById('progress-loader'));
		}
	}

	async function poll() {
		let answer;
		try {
			const response = await fetch('collect?' + collectQuery, { cache: 'no-store' });
			answer = await response.json();
		} catch (e) {
			setTimeout(poll, 2000);
			return;
		}
		if (answer.status === 'complete') {
			stopFrames();
			window.location.href = 'done?' + query;
		} else if (answer.status === 'pending') {
			if (answer.hintCode === 'started' || answer.hintCode === 'userSign') {
				showProgress();
			}
			setTimeout(poll, 2000);
		} else {
			redirectToError(answer.hintCode);
		}
	}

	if (qrcodeImg !== null) {
		frame();
		frames = setInterval(frame, 1000);
	}
	poll();
}
