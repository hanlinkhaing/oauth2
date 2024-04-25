const callCodeValidator = (callback) => {
    const codeModal = document.getElementById('code-modal');
    codeModal.style.display = 'block';
    document.getElementById('otc-1').select();
    document.getElementById('submit-code').onclick = async () => {
        const vCode = getCode(); // code.join('');
        console.log(vCode);
        if (vCode.length < 6) {
            showError('6 Digits needed!');
            return;
        }
        modalHide();
        callback(vCode);
    };
    document.getElementById('cancel-code').onclick = async () => {
        modalHide();
    };
    const modalHide = () => {
        ins.forEach(function (input) {
            input.value = '';
        });
        codeModal.style.display = 'none';
    };
};
