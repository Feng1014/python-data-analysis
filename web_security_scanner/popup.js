document.getElementById('scanButton').addEventListener('click', () => {
    chrome.runtime.sendMessage({ action: 'scanPage' }, (response) => {
        document.getElementById('result').textContent = JSON.stringify(response, null, 2);
    });
});

document.getElementById('customScan').addEventListener('click', () => {
    const rule = document.getElementById('customRule').value;
    if (rule) {
        chrome.runtime.sendMessage({ action: 'customScan', rule: rule }, (response) => {
            document.getElementById('result').textContent = JSON.stringify(response, null, 2);
        });
    }
});