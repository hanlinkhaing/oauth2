const toast = document.getElementById('toast');
const showError = (message) => {
    const errorMessage = document.getElementById('error-message');
    errorMessage.innerHTML = message;
    toast.hidden = false;
    setTimeout(function () {
        toast.hidden = true;
        errorMessage.innerHTML = '';
    }, 5000);
};

toast.onclick = () => (toast.hidden = true);

function parseJwt(token) {
    var base64Url = token.split('.')[1];
    var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    var jsonPayload = decodeURIComponent(
        window
            .atob(base64)
            .split('')
            .map(function (c) {
                return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
            })
            .join('')
    );

    return JSON.parse(jsonPayload);
}

function setCookie(name, value, options = { maxAge: 1000 * 60 * 60 * 24 * 7 }) {
    options = {
        path: '/',
        // add other defaults here if necessary
        ...options,
    };
    if (options.expires instanceof Date) {
        options.expires = options.expires.toUTCString();
    }
    let updatedCookie = encodeURIComponent(name) + '=' + encodeURIComponent(value);
    for (let optionKey in options) {
        updatedCookie += '; ' + optionKey;
        let optionValue = options[optionKey];
        if (optionValue !== true) {
            updatedCookie += '=' + optionValue;
        }
    }
    document.cookie = updatedCookie;
}

let in1 = document.getElementById('otc-1'),
    ins = document.querySelectorAll('input.otc-input'),
    splitNumber = function (e) {
        let data = e.data || e.target.value; // Chrome doesn't get the e.data, it's always empty, fallback to value then.
        if (!data) return; // Shouldn't happen, just in case.
        if (data.length === 1) return; // Here is a normal behavior, not a paste action.
        popuNext(e.target, data);
        //for (i = 0; i < data.length; i++ ) { ins[i].value = data[i]; }
    },
    popuNext = function (el, data) {
        el.value = data[0]; // Apply first item to first input
        data = data.substring(1); // remove the first char.
        if (el.nextElementSibling && data.length) {
            // Do the same with the next element and next data
            popuNext(el.nextElementSibling, data);
        }
    };

let code = [];
const setCode = (i) => {
    const value = i.value;
    if (value && code.length < 6) code.push(value[0]);
    else code.pop();
};

const getCode = () => {
    return `${document.getElementById('otc-1').value}${document.getElementById('otc-2').value}${
        document.getElementById('otc-3').value
    }${document.getElementById('otc-4').value}${document.getElementById('otc-5').value}${
        document.getElementById('otc-6').value
    }`;
};

ins.forEach(function (input) {
    input.addEventListener('keyup', function (e) {
        // Break if Shift, Tab, CMD, Option, Control.
        if (e.keyCode === 16 || e.keyCode == 9 || e.keyCode == 224 || e.keyCode == 18 || e.keyCode == 17) return;

        // On Backspace or left arrow, go to the previous field.
        if (
            (e.keyCode === 8 || e.keyCode === 37) &&
            this.previousElementSibling &&
            this.previousElementSibling.tagName === 'INPUT'
        ) {
            this.previousElementSibling.select();
        } else if (e.keyCode !== 8 && this.nextElementSibling) {
            this.nextElementSibling.select();
        }

        // If the target is populated to quickly, value length can be > 1
        if (e.target.value.length > 1) splitNumber(e);
        setCode(this);
    });

    input.addEventListener('focus', function (e) {
        // If the focus element is the first one, do nothing
        if (this === in1) return;

        // If value of input 1 is empty, focus it.
        if (in1.value == '') in1.focus();

        // If value of a previous input is empty, focus it.
        // To remove if you don't wanna force user respecting the fields order.
        if (this.previousElementSibling.value == '') this.previousElementSibling.focus();
    });
});

in1.addEventListener('input', splitNumber);
