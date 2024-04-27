const generateRandomCode = (charactersLength, isNumberOnly = false) => {
    let randomCode = '';
    let alphabets = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    let numbers = '0123456789';

    let idxNumber = 0;

    for (let i = 0; i < charactersLength; i++) {
        if (isNumberOnly) {
            randomCode += numbers.charAt(Math.floor(Math.random() * numbers.length));
            idxNumber++;
            continue;
        }

        if (Math.floor(Math.random() * 10) % 2 == 0) {
            if (idxNumber < 2) {
                randomCode += numbers.charAt(Math.floor(Math.random() * numbers.length));
                idxNumber++;
            } else {
                i--;
            }
        } else {
            if (idxNumber < 1 && randomCode.length == charactersLength - 1) {
                i--;
            } else {
                randomCode += alphabets.charAt(Math.floor(Math.random() * alphabets.length));
            }
        }
    }

    return randomCode;
};

module.exports = { generateRandomCode };
