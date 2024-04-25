const dropZoneInput = document.getElementById('photo');
const selectImage = document.getElementById('select-image');
const takeImage = document.getElementById('take-image');
const dropZoneElement = document.getElementById('drop-zone');
const takeImageModal = document.getElementById('take-image-modal');
const dropZonePrompt = document.getElementById('drop-zone-prompt');

window.onclick = (e) => {
    if ('take-image-modal' === e.target.id) closeModal();
};

selectImage.addEventListener('click', (e) => {
    dropZoneInput.click();
});

dropZoneInput.addEventListener('change', (e) => {
    if (dropZoneInput.files && dropZoneInput.files[0]) {
        const maxAllowedSize = 1 * 1024 * 1024;
        if (dropZoneInput.files[0].size > maxAllowedSize) {
            showError('Image is bigger than 1MB!');
            dropZoneInput.value = '';
            return;
        }
    }
    if (dropZoneInput.files.length) {
        updateThumbnail(dropZoneInput.files[0]);
    }
});

dropZoneElement.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZoneElement.classList.add('drop-zone--over');
});

['dragleave', 'dragend'].forEach((type) => {
    dropZoneElement.addEventListener(type, (e) => {
        dropZoneElement.classList.remove('drop-zone--over');
    });
});

dropZoneElement.addEventListener('drop', (e) => {
    e.preventDefault();

    if (e.dataTransfer.files.length) {
        dropZoneInput.files = e.dataTransfer.files;
        updateThumbnail(e.dataTransfer.files[0]);
    }

    dropZoneElement.classList.remove('drop-zone--over');
});

/**
 * Updates the thumbnail on a drop zone element.
 *
 * @param {HTMLElement} dropZoneElement
 * @param {File} file
 */
function updateThumbnail(file) {
    let thumbnailElement = dropZoneElement.querySelector('.drop-zone__thumb');

    // First time - remove the prompt
    if (dropZonePrompt) {
        dropZonePrompt.style.display = 'none';
    }

    // First time - there is no thumbnail element, so lets create it
    if (!thumbnailElement) {
        thumbnailElement = document.createElement('div');
        thumbnailElement.classList.add('drop-zone__thumb');
        closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.classList.add('btn-close');
        closeBtn.addEventListener('click', () => {
            thumbnailElement.remove();
            dropZonePrompt.style.display = 'inline-block';
        });
        thumbnailElement.appendChild(closeBtn);
        dropZoneElement.appendChild(thumbnailElement);
    }

    thumbnailElement.dataset.label = file.name;

    // Show thumbnail for image files
    if (file.type.startsWith('image/')) {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = () => {
            thumbnailElement.style.backgroundImage = `url('${reader.result}')`;
        };
    } else {
        thumbnailElement.style.backgroundImage = null;
    }
}

const cameraButton = document.getElementById('start-camera');
// const startCameraDiv = document.getElementById('start-camera-div');
const cameraDiv = document.getElementById('camera-div');
const video = document.getElementById('video');
const takePhoto = document.getElementById('take-photo');
const canvas = document.getElementById('canvas');
const changeCamera = document.getElementById('change-camera');
const closeCamera = document.getElementById('close-camera');
changeCamera.style.display = 'none';
closeCamera.style.display = 'none';

const toggleFlip = () => {
    if (video.srcObject) {
        if (video.srcObject.getTracks()[0].getConstraints().facingMode === 'user') video.style.transform = 'scaleX(-1)';
        else if (video.srcObject.getTracks()[0].getConstraints().facingMode === 'environment')
            video.style.transform = null;
    }
};

let front = true;
const stopCurrentStream = () => {
    if (video.srcObject) {
        video.srcObject.getTracks()[0].stop();
        video.srcObject = null;
    }
};

const constraints = {
    video: {
        facingMode: 'user',
        width: { min: 720, ideal: 1024, max: 1024 },
        height: { min: 720, ideal: 1024, max: 1024 },
    },
    audio: false,
};

if (
    /(android|bb\d+|meego).+mobile|avantgo|bada\/|blackberry|blazer|compal|elaine|fennec|hiptop|iemobile|ip(hone|od)|ipad|iris|kindle|Android|Silk|lge |maemo|midp|mmp|netfront|opera m(ob|in)i|palm( os)?|phone|p(ixi|re)\/|plucker|pocket|psp|series(4|6)0|symbian|treo|up\.(browser|link)|vodafone|wap|windows (ce|phone)|xda|xiino/i.test(
        navigator.userAgent
    ) ||
    /1207|6310|6590|3gso|4thp|50[1-6]i|770s|802s|a wa|abac|ac(er|oo|s\-)|ai(ko|rn)|al(av|ca|co)|amoi|an(ex|ny|yw)|aptu|ar(ch|go)|as(te|us)|attw|au(di|\-m|r |s )|avan|be(ck|ll|nq)|bi(lb|rd)|bl(ac|az)|br(e|v)w|bumb|bw\-(n|u)|c55\/|capi|ccwa|cdm\-|cell|chtm|cldc|cmd\-|co(mp|nd)|craw|da(it|ll|ng)|dbte|dc\-s|devi|dica|dmob|do(c|p)o|ds(12|\-d)|el(49|ai)|em(l2|ul)|er(ic|k0)|esl8|ez([4-7]0|os|wa|ze)|fetc|fly(\-|_)|g1 u|g560|gene|gf\-5|g\-mo|go(\.w|od)|gr(ad|un)|haie|hcit|hd\-(m|p|t)|hei\-|hi(pt|ta)|hp( i|ip)|hs\-c|ht(c(\-| |_|a|g|p|s|t)|tp)|hu(aw|tc)|i\-(20|go|ma)|i230|iac( |\-|\/)|ibro|idea|ig01|ikom|im1k|inno|ipaq|iris|ja(t|v)a|jbro|jemu|jigs|kddi|keji|kgt( |\/)|klon|kpt |kwc\-|kyo(c|k)|le(no|xi)|lg( g|\/(k|l|u)|50|54|\-[a-w])|libw|lynx|m1\-w|m3ga|m50\/|ma(te|ui|xo)|mc(01|21|ca)|m\-cr|me(rc|ri)|mi(o8|oa|ts)|mmef|mo(01|02|bi|de|do|t(\-| |o|v)|zz)|mt(50|p1|v )|mwbp|mywa|n10[0-2]|n20[2-3]|n30(0|2)|n50(0|2|5)|n7(0(0|1)|10)|ne((c|m)\-|on|tf|wf|wg|wt)|nok(6|i)|nzph|o2im|op(ti|wv)|oran|owg1|p800|pan(a|d|t)|pdxg|pg(13|\-([1-8]|c))|phil|pire|pl(ay|uc)|pn\-2|po(ck|rt|se)|prox|psio|pt\-g|qa\-a|qc(07|12|21|32|60|\-[2-7]|i\-)|qtek|r380|r600|raks|rim9|ro(ve|zo)|s55\/|sa(ge|ma|mm|ms|ny|va)|sc(01|h\-|oo|p\-)|sdk\/|se(c(\-|0|1)|47|mc|nd|ri)|sgh\-|shar|sie(\-|m)|sk\-0|sl(45|id)|sm(al|ar|b3|it|t5)|so(ft|ny)|sp(01|h\-|v\-|v )|sy(01|mb)|t2(18|50)|t6(00|10|18)|ta(gt|lk)|tcl\-|tdg\-|tel(i|m)|tim\-|t\-mo|to(pl|sh)|ts(70|m\-|m3|m5)|tx\-9|up(\.b|g1|si)|utst|v400|v750|veri|vi(rg|te)|vk(40|5[0-3]|\-v)|vm40|voda|vulc|vx(52|53|60|61|70|80|81|83|85|98)|w3c(\-| )|webc|whit|wi(g |nc|nw)|wmlb|wonu|x700|yas\-|your|zeto|zte\-/i.test(
        navigator.userAgent.substr(0, 4)
    )
) {
    changeCamera.style.display = 'inline-block';
    closeCamera.style.display = 'inline-block';
    changeCamera.addEventListener('click', async function () {
        front = !front;
        stopCurrentStream();
        try {
            constraints.video.facingMode = front ? 'user' : 'environment';
            const stream = await navigator.mediaDevices.getUserMedia(constraints);
            video.srcObject = stream;
            toggleFlip();
        } catch (err) {
            showError(err.message);
            closeModal();
        }
    });
}

takePhoto.addEventListener('click', function () {
    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    if (video.srcObject.getTracks()[0].getConstraints().facingMode === 'user') {
        canvas.getContext('2d').translate(canvas.width, 0);
        canvas.getContext('2d').scale(-1, 1);
    }
    canvas.getContext('2d').drawImage(video, 0, 0, canvas.width, canvas.height);
    canvas.toBlob((blob) => {
        try {
            const file = new File([blob], 'photo.png', { type: 'image/png' });
            const dT = new DataTransfer();
            dT.items.add(file);
            dropZoneInput.files = dT.files;
            stopCurrentStream();
            updateThumbnail(file);
            closeModal();
        } catch (err) {
            showError(err.message);
            closeModal();
        }
    });
});

const closeModal = () => {
    stopCurrentStream();
    takeImageModal.style.display = 'none';
};

takeImage.addEventListener('click', async (e) => {
    takeImageModal.style.display = 'block';
    try {
        const stream = await navigator.mediaDevices.getUserMedia(constraints);
        video.srcObject = stream;
        toggleFlip();
    } catch (err) {
        showError(err.message);
        closeModal();
    }
});

document.getElementById('close-camera').addEventListener('click', () => closeModal());
