"use strict";
const { v4: uuidv4 } = require("uuid");
const crypto = require('crypto');
const axios = require('axios');
const moment = require('moment');
const request = require('request');
const momoModel = require('../models/momo.model');
const transferModel = require('../models/transfer.model');
const logHelper = require('../helpers/log.helper');
axios.defaults.timeout = 20 * 1000;

exports.randomDevice = () => {
    let listDevice = [
        { "name": "Samsung Galaxy S21 Ultra 5G", "deviceOS": "ANDROID", "hardware": "Exynos 2100, Snapdragon 888", "facture": "Samsung", "MODELID": "Samsung Galaxy S21 Ultra 5G" },
        { "name": "iPhone 12 Pro Max", "deviceOS": "iOS", "hardware": "A14 Bionic", "facture": "Apple", "MODELID": "iPhone 12 Pro Max" },
        { "name": "OnePlus 9 Pro 5G", "deviceOS": "ANDROID", "hardware": "Snapdragon 888", "facture": "OnePlus", "MODELID": "OnePlus 9 Pro 5G" },
        { "name": "Xiaomi Mi 11", "deviceOS": "ANDROID", "hardware": "Snapdragon 888", "facture": "Xiaomi", "MODELID": "Xiaomi Mi 11" },
        { "name": "Google Pixel 5", "deviceOS": "ANDROID", "hardware": "Snapdragon 765G", "facture": "Google", "MODELID": "Google Pixel 5" },
        { "name": "Sony Xperia 1 II", "deviceOS": "ANDROID", "hardware": "Snapdragon 865", "facture": "Sony", "MODELID": "Sony Xperia 1 II" },
        { "name": "Samsung Galaxy Z Flip 3 5G", "deviceOS": "ANDROID", "hardware": "Snapdragon 888", "facture": "Samsung", "MODELID": "Samsung Galaxy Z Flip 3 5G" },
        { "name": "Asus ROG Phone 5", "deviceOS": "ANDROID", "hardware": "Snapdragon 888", "facture": "Asus", "MODELID": "Asus ROG Phone 5" }
    ];
    return listDevice[Math.floor(Math.random() * listDevice.length)];
}

exports.randomString = (length, characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') => {
    let result = '';
    const charactersLength = characters.length;
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }
    return result;
}

exports.diffHours = (date, otherDate) => Math.abs(date - otherDate) / (1000 * 60 * 60);

exports.getToken = () => `${this.randomString(22)}:${this.randomString(9)}-${this.randomString(20)}-${this.randomString(12)}-${this.randomString(7)}-${this.randomString(7)}-${this.randomString(53)}-${this.randomString(9)}_${this.randomString(11)}-${this.randomString(4)}`;

exports.sha256 = (data) => crypto.createHash("sha256").update(data).digest("hex");

exports.decryptString = (data, key) => {
    let iv = Buffer.alloc(16);
    let cipher = crypto.createDecipheriv("aes-256-cbc", key.substring(0, 32), iv);
    return cipher.update(data, "base64") + cipher.final("utf8");
}

exports.encryptString = (data, key) => {
    let iv = Buffer.alloc(16);
    let cipher = crypto.createCipheriv("aes-256-cbc", key.substr(0, 32), iv);
    return Buffer.concat([cipher.update(data, "utf8"), cipher.final()]).toString("base64");
}

exports.encryptRSA = (data, publicKey) => crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, Buffer.from(data)).toString("base64");

exports.checkSum = (phone, type, times, setupKey) => this.encryptString(`${phone}${times}000000${type}${times / 1000000000000.0}E12`, setupKey);

exports.convertPhone = (number) => {
    let arrPrefix = {
        "016966": "03966",
        "0169": "039",
        "0168": "038",
        "0167": "037",
        "0166": "036",
        "0165": "035",
        "0164": "034",
        "0163": "033",
        "0162": "032",
        "0120": "070",
        "0121": "079",
        "0122": "077",
        "0126": "076",
        "0128": "078",
        "0123": "083",
        "0124": "084",
        "0125": "085",
        "0127": "081",
        "0129": "082",
        "01992": "059",
        "01993": "059",
        "01998": "059",
        "01999": "059",
        "0186": "056",
        "0188": "058"
    }
    try {
        number = number.replace(/\D/g, '');
        for (let prefix in arrPrefix) {
            if (number.includes(prefix) && number.substr(0, prefi.length) == prefix) {
                number = `${arrPrefix[prefix]}${number.substr(prefix.length, (number.length - prefix.length))}`;
                break;
            }
        }
        return number;
    } catch (err) {
        console.log(err);
        return number;
    }
}

exports.regexPhone = (phone) => /(84|0[3|5|7|8|9])+([0-9]{8})\b/g.test(phone);

exports.userCheck = async (phone) => {
    try {
        let times = new Date().getTime(), dataDevice = this.randomDevice(), imei = uuidv4(), SECUREID = this.randomString(17, '0123456789abcdef');
        const dataPhone = await momoModel.findOne({ phone });
        if (dataPhone) {
            dataDevice = dataPhone.dataDevice;
            imei = dataPhone.imei;
            SECUREID = dataPhone.SECUREID;
        }
        let options = {
            method: 'POST',
            url: 'https://api.momo.vn/backend/auth-app/public/CHECK_USER_BE_MSG',
            headers: {
                'msgtype': 'CHECK_USER_BE_MSG',
                'Content-Type': 'application/json'
            },
            data: JSON.stringify({
                user: phone,
                msgType: "CHECK_USER_BE_MSG",
                cmdId: times + "000000",
                lang: "vi",
                time: times,
                channel: "APP",
                appVer: process.env.appVer,
                appCode: process.env.appCode,
                deviceOS: dataDevice.deviceOS,
                buildNumber: 0,
                appId: "vn.momo.platform",
                result: true,
                errorCode: 0,
                errorDesc: "",
                momoMsg: {
                    _class: "mservice.backend.entity.msg.RegDeviceMsg",
                    number: phone,
                    imei,
                    cname: "Vietnam",
                    ccode: "084",
                    device: dataDevice.name,
                    firmware: "25",
                    hardware: dataDevice.hardware,
                    manufacture: dataDevice.facture,
                    csp: "",
                    icc: "",
                    mcc: "",
                    device_os: dataDevice.deviceOS,
                    secure_id: SECUREID
                }
            })
        };
        let { data: response } = await axios(options);

        if (!response.result) {
            return ({
                success: false,
                message: response.errorDesc
            })
        } else if (response.extra.IDENTITY_KEY == 'BL_FM') {
            return ({
                success: false,
                message: `Cần xác thực khuôn mặt!`
            })
        } else {
            await momoModel.findOneAndUpdate({ phone }, { $set: { phone, SECUREID, imei, dataDevice, status: 'pending', loginStatus: 'waitSend' } }, { upsert: true })
            return ({
                success: true,
                message: 'Success!'
            })
        }

    } catch (err) {
        return ({
            success: false,
            message: 'Có lỗi xảy ra ' + err.message || err
        })
    }
}

exports.sendOTP = async (phone, password) => {
    try {
        let check = await this.userCheck(phone);
        if (!check.success) return check;

        let dataPhone = await momoModel.findOne({ phone });

        if (!dataPhone) {
            return ({
                success: false,
                message: 'Không tìm thấy dữ liệu số điện thoại này hoặc lỗi'
            })
        }

        const dataDevice = dataPhone.dataDevice;
        let times = new Date().getTime(), rkey = this.randomString(20), AAID = uuidv4(), TOKEN = this.getToken();

        let options = {
            method: 'POST',
            url: 'https://api.momo.vn/backend/otp-app/public/',
            headers: {
                'msgtype': 'SEND_OTP_MSG',
                'app_version': process.env.appVer,
                'app_code': process.env.appCode,
                'Content-Type': 'application/json'
            },
            data: JSON.stringify({
                user: phone,
                msgType: "SEND_OTP_MSG",
                cmdId: times + "000000",
                lang: "vi",
                time: times,
                channel: "APP",
                appVer: process.env.appVer,
                appCode: process.env.appCode,
                deviceOS: dataDevice.deviceOS,
                buildNumber: 0,
                appId: "vn.momo.platform",
                result: true,
                errorCode: 0,
                errorDesc: "",
                momoMsg: {
                    _class: "mservice.backend.entity.msg.RegDeviceMsg",
                    number: phone,
                    imei: dataPhone.imei,
                    cname: "Vietnam",
                    ccode: "084",
                    device: dataDevice.name,
                    firmware: "25",
                    hardware: dataDevice.hardware,
                    manufacture: dataDevice.facture,
                    csp: "",
                    icc: "",
                    mcc: "",
                    device_os: dataDevice.deviceOS,
                    secure_id: dataDevice.SECUREID
                },
                extra: {
                    action: "SEND",
                    rkey,
                    AAID,
                    IDFA: "",
                    TOKEN,
                    SIMULATOR: "",
                    SECUREID: dataDevice.SECUREID,
                    MODELID: dataDevice.MODELID,
                    isVoice: true,
                    REQUIRE_HASH_STRING_OTP: true,
                    checkSum: ""
                }
            })
        };
        let { data: response } = await axios(options);

        if (!response.result) {
            return ({
                success: false,
                message: response.errorDesc
            })
        }

        await momoModel.findOneAndUpdate({ phone }, { $set: { phone, password, rkey, AAID, TOKEN, loginStatus: 'waitOTP' } }, { upsert: true })
        return ({
            success: true,
            message: 'Gửi OTP thành công!'
        })

    } catch (err) {
        return ({
            success: false,
            message: 'Có lỗi xảy ra ' + err.message || err
        })
    }

}

exports.confirmOTP = async (phone, otp) => {
    try {
        let dataPhone = await momoModel.findOne({ phone, loginStatus: 'waitOTP' });

        if (!dataPhone) {
            return ({
                success: false,
                message: 'Không tìm thấy dữ liệu số điện thoại này hoặc lỗi'
            })
        }

        const dataDevice = dataPhone.dataDevice;
        let times = new Date().getTime();

        let options = {
            method: 'POST',
            url: 'https://api.momo.vn/backend/otp-app/public/',
            headers: {
                'msgtype': 'REG_DEVICE_MSG',
                'userhash': crypto.createHash("md5").update(phone).digest("hex"),
                'Content-Type': 'application/json'
            },
            data: JSON.stringify({
                user: phone,
                msgType: "REG_DEVICE_MSG",
                cmdId: times + "000000",
                lang: "vi",
                time: times,
                channel: "APP",
                appVer: process.env.appVer,
                appCode: process.env.appCode,
                deviceOS: dataDevice.deviceOS,
                buildNumber: 0,
                appId: "vn.momo.platform",
                result: true,
                errorCode: 0,
                errorDesc: "",
                momoMsg: {
                    _class: "mservice.backend.entity.msg.RegDeviceMsg",
                    number: phone,
                    imei: dataPhone.imei,
                    cname: "Vietnam",
                    ccode: "084",
                    device: dataDevice.name,
                    firmware: "25",
                    hardware: dataDevice.hardware,
                    manufacture: dataDevice.facture,
                    csp: "",
                    icc: "",
                    mcc: "",
                    device_os: dataDevice.deviceOS,
                    secure_id: dataPhone.SECUREID
                },
                extra: {
                    ohash: crypto.createHash("sha256").update(phone + dataPhone.rkey + otp).digest("hex"),
                    AAID: dataPhone.AAID,
                    IDFA: "",
                    TOKEN: dataPhone.TOKEN,
                    SIMULATOR: "",
                    SECUREID: dataPhone.SECUREID,
                    MODELID: dataDevice.MODELID,
                    checkSum: ""
                }
            })
        };
        let { data: response } = await axios(options);
        console.log(response)

        if (!response.result) {
            return ({
                success: false,
                message: response.errorDesc
            })
        }

        let setupKey = this.decryptString(response.extra.setupKey, response.extra.ohash), phash = this.encryptString(`${dataPhone.imei}|${dataPhone.password}`, setupKey);
        let name = response.extra.NAME;

        await momoModel.findOneAndUpdate({ phone }, { $set: { name, setupKey, phash, loginStatus: 'waitLogin' } }, { upsert: true })
        return ({
            success: true,
            message: 'Xác thực OTP thành công, đợi đăng nhập!'
        })

    } catch (err) {
        return ({
            success: false,
            message: 'Có lỗi xảy ra ' + err.message || err
        })
    }
}

exports.login = async (phone) => {
    try {
        let dataPhone = await momoModel.findOne({ phone });

        if (!dataPhone) {
            return ({
                success: false,
                message: 'Không tìm thấy dữ liệu số điện thoại này hoặc lỗi'
            })
        }

        const dataDevice = dataPhone.dataDevice;
        let times = new Date().getTime();

        let options = {
            method: 'POST',
            url: 'https://owa.momo.vn/public/login',
            headers: {
                'msgtype': 'USER_LOGIN_MSG',
                'Content-Type': 'application/json'
            },
            data: JSON.stringify({
                user: phone,
                msgType: "USER_LOGIN_MSG",
                pass: dataPhone.password,
                cmdId: times + "000000",
                lang: "vi",
                time: times,
                channel: "APP",
                appVer: process.env.appVer,
                appCode: process.env.appCode,
                deviceOS: dataDevice.deviceOS,
                buildNumber: 0,
                appId: "vn.momo.platform",
                result: true,
                errorCode: 0,
                errorDesc: "",
                momoMsg: {
                    _class: "mservice.backend.entity.msg.LoginMsg",
                    isSetup: false
                },
                extra: {
                    pHash: dataPhone.phash,
                    AAID: dataPhone.AAID,
                    IDFA: "",
                    TOKEN: dataPhone.TOKEN,
                    SIMULATOR: "",
                    SECUREID: dataPhone.SECUREID,
                    MODELID: dataDevice.MODELID,
                    checkSum: this.checkSum(phone, "USER_LOGIN_MSG", times, dataPhone.setupKey)
                }
            })
        };

        let { data: response } = await axios(options);

        if (!response.result) {
            await momoModel.findOneAndUpdate({ phone }, { $set: { loginStatus: 'errorLogin', description: response.errorDesc } });
            await logHelper.create('momoLogin', `Đăng nhập thất bại!\n* [ ${phone} ]\n* [ Có lỗi xảy ra ${response.errorDesc} ]`);
            return ({
                success: false,
                message: response.errorDesc
            })
        }

        let AUTH_TOKEN = response.extra.AUTH_TOKEN, REFRESH_TOKEN = response.extra.REFRESH_TOKEN, REQUEST_ENCRYPT_KEY = response.extra.REQUEST_ENCRYPT_KEY;
        await momoModel.findOneAndUpdate({ phone }, { $set: { amount: response.extra.BALANCE ?? 0, AUTH_TOKEN, REFRESH_TOKEN, REQUEST_ENCRYPT_KEY, loginAt: new Date(), loginStatus: 'active' } }, { upsert: true })

        return ({
            success: true,
            message: 'Đăng nhập thành công!'
        })

    } catch (err) {
        await momoModel.findOneAndUpdate({ phone }, { $set: { loginStatus: 'errorLogin', description: 'Có lỗi xảy ra ' + err.message || err } });
        await logHelper.create('momoLogin', `Đăng nhập thất bại!\n* [ ${phone} ]\n* [ Có lỗi xảy ra ${err.message || err} ]`);
        return ({
            success: false,
            message: 'Có lỗi xảy ra ' + err.message || err
        })
    }
}

exports.checkSession = async (phone, refresh = false) => {
    const dataPhone = await momoModel.findOne({ phone, AUTH_TOKEN: { $exists: true } });

    if (!dataPhone) {
        return ({
            success: false,
            message: 'Không tìm thấy dữ liệu số điện thoại này hoặc lỗi'
        })
    }

    return ((new Date() - dataPhone.loginAt) > 1000000 || refresh) ? await this.refreshToken(phone) : ({
        success: true,
        message: 'Session is vaild',
        data: dataPhone
    });
}

exports.refreshToken = async (phone) => {
    try {
        const dataPhone = await momoModel.findOne({ phone, REFRESH_TOKEN: { $exists: true } });

        if (!dataPhone) {
            return ({
                success: false,
                phone,
                message: 'Không tìm thấy dữ liệu số điện thoại này hoặc lỗi',
            })
        }

        const dataDevice = dataPhone.dataDevice;
        let times = new Date().getTime();

        let options = {
            method: 'POST',
            url: 'https://api.momo.vn/auth/fast-login/refresh-token',
            headers: {
                'Authorization': 'Bearer ' + dataPhone.REFRESH_TOKEN,
                'msgtype': 'REFRESH_TOKEN_MSG',
                'Content-Type': 'application/json',
            },
            data: JSON.stringify({
                user: dataPhone.phone,
                msgType: "REFRESH_TOKEN_MSG",
                cmdId: times + "000000",
                lang: "vi",
                time: times,
                channel: "APP",
                appVer: process.env.appVer,
                appCode: process.env.appCode,
                deviceOS: dataDevice.deviceOS,
                buildNumber: 0,
                appId: "vn.momo.platform",
                momoMsg: {
                    _class: "mservice.backend.entity.msg.RefreshAccessTokenMsg",
                    accessToken: dataPhone.AUTH_TOKEN
                },
                extra: {
                    AAID: dataPhone.AAID,
                    IDFA: "",
                    TOKEN: dataPhone.TOKEN,
                    ONESIGNAL_TOKEN: dataPhone.TOKEN,
                    SIMULATOR: false,
                    MODELID: dataDevice.MODELID,
                    DEVICE_TOKEN: "",
                    checkSum: this.checkSum(phone, "REFRESH_TOKEN_MSG", times, dataPhone.setupKey),
                },
            }),
        };

        let { data: response } = await axios(options);
        console.log(response);

        if (!response.result) {
            await momoModel.findOneAndUpdate({ phone }, { $set: { loginStatus: 'waitLogin' } }, { upsert: true })
            let reLogin = await this.login(phone);

            return reLogin.success ? ({
                success: true,
                phone,
                message: 'Đăng nhập lại thành công!',
                data: await momoModel.findOne({ phone })
            }) : reLogin
        }

        let AUTH_TOKEN = response.extra.AUTH_TOKEN;
        console.log(AUTH_TOKEN);
        await momoModel.findOneAndUpdate({ phone }, { $set: { AUTH_TOKEN, loginAt: new Date(), loginStatus: 'active' } }, { upsert: true });

        return ({
            success: true,
            phone,
            message: 'refreshToken thành công!',
            data: await momoModel.findOne({ phone })
        });

    } catch (err) {
        await momoModel.findOneAndUpdate({ phone }, { $set: { loginStatus: 'refreshError', description: 'Có lỗi xảy ra ' + err.message || err } }, { upsert: true })
        //await logHelper.create('refreshToken', `refreshToken thất bại!\n* [ ${phone} ]\n* [ Có lỗi xảy ra ${err.message || err} ]`);
        return ({
            success: false,
            phone,
            message: 'Có lỗi xảy ra ' + err.message || err,
        });
    }
}

exports.getHistory = async (phone, configHistory, hours = 24) => {
    try {
        const times = new Date().getTime();
        const checkSession = await this.checkSession(phone);

        if (!checkSession.success) {
            return checkSession;
        }

        const dataPhone = checkSession.data;
        const dataDevice = dataPhone.dataDevice;

        if (configHistory.dataType == 'noti') {
            let options = {
                method: 'POST',
                url: 'https://m.mservice.io/hydra/v2/user/noti',
                headers: {
                    'userid': phone,
                    'Authorization': 'Bearer ' + dataPhone.AUTH_TOKEN,
                    'Content-Type': 'application/json'
                },
                data: JSON.stringify({
                    userId: phone,
                    fromTime: times - (360000 * hours),
                    toTime: times,
                    limit: 5000,
                    cursor: ""
                })
            };

            let { data: response } = await axios(options);

            if (!response.success) {
                return ({
                    success: false,
                    message: response.message.responseInfo.errorMessage ?? 'Không tìm thấy lịch sử!'
                })
            }

            let dataHistory = [], i = 0;

            for (const data of response.message.data.notifications) {
                if (i >= configHistory.limit) break;

                let extra = JSON.parse(data.extra);
                if (!data.sender || !data.caption.includes('đ từ')) continue;

                dataHistory.push({
                    io: 1,
                    phone,
                    transId: extra.tranId || data.tranId,
                    partnerId: extra.partnerId || data.sender,
                    partnerName: extra.partnerName || (extra.partnerId || data.sender),
                    targetId: data.receiverNumber,
                    targetName: data.receiverNumber,
                    amount: data.caption.split('đ từ')[0].replace(/[^\d]/g, '') || Math.round(extra.amount),
                    comment: extra.comment || (data.body == 'Nhấn để xem chi tiết.' ? null : data.body.split('"')[1]) || null,
                    time: data.time
                })
                i++;
            }

            return ({
                success: true,
                message: 'Lấy thành công!',
                data: dataHistory
            })

        }

        let key = crypto.randomBytes(32).toString("hex").substring(32), requestkey = this.encryptRSA(key, dataPhone.REQUEST_ENCRYPT_KEY);
        let options = {
            method: 'POST',
            url: 'https://api.momo.vn/transhis/api/transhis/browse',
            headers: {
                'requestkey': requestkey,
                'userid': phone,
                'Authorization': 'Bearer ' + dataPhone.AUTH_TOKEN,
                'Content-Type': 'application/json'
            },
            data: this.encryptString(JSON.stringify({
                requestId: times,
                startDate: new Date().toLocaleDateString(),
                endDate: new Date().toLocaleDateString(),
                offset: 0,
                limit: configHistory.limit,
                appCode: process.env.appCode,
                appVer: process.env.appVer,
                lang: "vi",
                deviceOS: dataDevice.deviceOS,
                channel: "APP",
                buildNumber: 8952,
                client: "sync_app",
                appId: "vn.momo.transactionhistory"
            }), key)
        };

        let { data: response } = await axios(options);

        response = this.decryptString(response, key);

        if (!response.includes('momoMsg') || JSON.parse(response).resultCode != 0) {
            return ({
                success: false,
                message: 'Lấy lịch sử thất bại!'
            })
        }

        response = JSON.parse(response);
        
        return ({
            success: true,
            message: 'Lấy thành công!',
            data: response.momoMsg
        })

    } catch (err) {
        await momoModel.findOneAndUpdate({ phone }, { $set: { description: 'getHistory| Có lỗi xảy ra ' + err.message || err } })
        return ({
            success: false,
            message: 'Có lỗi xảy ra ' + err.message || err
        })
    }
}

exports.getDetails = async (phone, transId) => {
    try {
        let times = new Date().getTime();
        const checkSession = await this.checkSession(phone);
        if (!checkSession.success) return checkSession;
        const dataPhone = checkSession.data;

        const dataDevice = dataPhone.dataDevice;
        let key = crypto.randomBytes(32).toString("hex").substring(32), requestkey = this.encryptRSA(key, dataPhone.REQUEST_ENCRYPT_KEY);

        let options = {
            method: 'POST',
            url: 'https://api.momo.vn/transhis/api/transhis/detail',
            headers: {
                'requestkey': requestkey,
                'userid': phone,
                'Authorization': 'Bearer ' + dataPhone.AUTH_TOKEN,
                'Content-Type': 'application/json'
            },
            data: this.encryptString(JSON.stringify({
                requestId: times,
                transId,
                appCode: process.env.appCode,
                appVer: process.env.appVer,
                lang: "vi",
                deviceOS: dataDevice.deviceOS,
                channel: "APP",
                buildNumber: 0,
                appId: ""
            }), key)
        };

        let { data: response } = await axios(options);

        response = JSON.parse(this.decryptString(response, key));

        if (response.resultCode != 0 || response.momoMsg.status == 6) {
            return ({
                success: false,
                message: `Không tìm thấy chi tiết lịch sử #${transId}!`
            })
        }

        let comment = response.momoMsg.serviceData ? JSON.parse(response.momoMsg.serviceData).COMMENT_VALUE : (response.momoMsg.oldData ? JSON.parse(response.momoMsg.oldData).commentValue : null);

        return ({
            success: true,
            message: 'Lấy thành công!',
            data: {
                io: response.momoMsg.io,
                status: response.momoMsg.status,
                phone,
                transId: response.momoMsg.transId,
                partnerId: response.momoMsg.sourceId,
                partnerName: response.momoMsg.sourceName,
                targetId: response.momoMsg.targetId,
                targetName: response.momoMsg.targetName,
                amount: response.momoMsg.totalOriginalAmount,
                postBalance: response.momoMsg.postBalance,
                comment,
                time: response.momoMsg.lastUpdate,
            }
        })

    } catch (err) {
        console.log(err);
        await momoModel.findOneAndUpdate({ phone }, { $set: { description: 'getDetails| Có lỗi xảy ra ' + err.message || err } })
        return ({
            success: false,
            message: 'Có lỗi xảy ra ' + err.message || err
        })
    }
}

 exports.getBalance = async (phone) => {
     let times = new Date().getTime();
     const checkSession = await this.checkSession(phone);
     if (!checkSession.success) return checkSession;
     const dataPhone = checkSession.data;

     const dataDevice = dataPhone.dataDevice;
     let key = crypto.randomBytes(32).toString("hex").substring(32), requestkey = this.encryptRSA(key, dataPhone.REQUEST_ENCRYPT_KEY);

     let options = {
        method: 'POST',
         url: 'https://api.momo.vn/sof/default-money/api',
         headers: {
             'requestkey': requestkey,
             'userid': phone,
             'msgtype': 'SOF_GET_DEFAULT_MONEY',
            'Authorization': 'Bearer ' + dataPhone.AUTH_TOKEN,
            'Content-Type': 'application/json'
       },
       body: this.encryptString(JSON.stringify({
            user: phone,
             msgType: "SOF_GET_DEFAULT_MONEY",
             cmdId: times + "000000",
            lang: "vi",
          time: times,
            channel: "APP",
             appVer: process.env.appVer,
            appCode: process.env.appCode,
            deviceOS: dataDevice.deviceOS,
             buildNumber: 428,
             appId: "vn.momo.sof",
             result: true,
             errorCode: 0,
            errorDesc: "",
             momoMsg: {
                 _class: "mservice.backend.entity.msg.ForwardMsg"
             },
             extra: {
                 checkSum: this.checkSum(phone, "SOF_GET_DEFAULT_MONEY", times, dataPhone.setupKey)
             }
         }), key)
     };

     return new Promise((resolve, reject) => {
         request(options, async (err, response, body) => {
            try {
                 body = JSON.parse(this.decryptString(body, key));
                 return body.result ? await momoModel.findOneAndUpdate({ phone }, { $set: { amount: body.momoMsg.sofInfo[0].balance } }, { upsert: true }) && resolve({
                     success: true,
                    message: 'Lấy thành công!',
                     balance: body.momoMsg.sofInfo[0].balance
                 }) : resolve({
                    success: false,
                    message: body.errorDesc
					})
             } catch (err) {
                 await momoModel.findOneAndUpdate({ phone }, { $set: { description: 'SOF_GET_DEFAULT_MONEY| Có lỗi xảy ra ' + err.message || err } })
                 return resolve({
                     success: false,
                    message: 'Có lỗi xảy ra ' + err
                 })
             }
        })
    })
 }

//exports.getBalance = async (phone) => {
 //   try {
 //       let times = new Date().getTime();
  //      const checkSession = await this.checkSession(phone);
  //      if (!checkSession.success) return checkSession;
   //     const dataPhone = checkSession.data;
//
  //      const dataDevice = dataPhone.dataDevice;
 //       let key = crypto.randomBytes(32).toString("hex").substring(32), requestkey = this.encryptRSA(key, dataPhone.REQUEST_ENCRYPT_KEY);
//
 //       let options = {
 //           method: 'POST',
   //         url: 'https://api.momo.vn/backend/sof/api/SOF_LIST_MANAGER_MSG',
   //         headers: {
    //            'requestkey': requestkey,
   //             'userid': phone,
    //            'msgtype': 'SOF_LIST_MANAGER_MSG',
    //            'Authorization': 'Bearer ' + dataPhone.AUTH_TOKEN,
       //         'Content-Type': 'application/json'
     //       },
       //     data: this.encryptString(JSON.stringify({
       //         user: phone,
      //          msgType: "SOF_LIST_MANAGER_MSG",
      //          cmdId: times + "000000",
       //         lang: "vi",
      //          time: times,
       //         channel: "APP",
       //         appVer: process.env.appVer,
       //         appCode: process.env.appCode,
        //        deviceOS: dataDevice.deviceOS,
        //        buildNumber: 0,
        //        appId: "",
        //        result: true,
       //         errorCode: 0,
       //         errorDesc: "",
       //         pass: "",
       //         momoMsg: {
    //                _class: "mservice.backend.entity.msg.ForwardMsg",
      //          },
    //            extra: {
     //               checkSum: this.checkSum(phone, "SOF_LIST_MANAGER_MSG", times, dataPhone.setupKey)
    //            }
      //      }), key)
      //  };
//
     //   let { data: response } = await axios(options);
//
     //   response = JSON.parse(this.decryptString(response, key));
//
      //  return response.result ? await momoModel.findOneAndUpdate({ phone }, { $set: { amount: response.momoMsg.sofInfo[0].balance } }, { upsert: true }) && ({
        //    success: true,
       //     message: 'Lấy thành công!',
         //   balance: response.momoMsg.sofInfo[0].balance
      //  }) : ({
     //       success: false,
    //        message: response.errorDesc
    //    })
    //} catch (err) {
   //     console.log(err);
    //    await momoModel.findOneAndUpdate({ phone }, { $set: { description: 'getBalance| Có lỗi xảy ra ' + err.message || err } })
    //    return ({
  //          success: false,
    //        message: 'Có lỗi xảy ra ' + err.message || err
       // })
   // }
//}

exports.checkName = async (phone, receiver) => {
    try {
        const times = new Date().getTime();
        const checkSession = await this.checkSession(phone);

        if (!checkSession.success) {
            return checkSession;
        }

        const dataPhone = checkSession.data;
        const dataDevice = dataPhone.dataDevice;
        let key = crypto.randomBytes(32).toString("hex").substring(32), requestkey = this.encryptRSA(key, dataPhone.REQUEST_ENCRYPT_KEY);

        let options = {
            method: 'POST',
            url: 'https://owa.momo.vn/api/CHECK_USER_PRIVATE',
            headers: {
                'requestkey': requestkey,
                'userid': phone,
                'msgtype': 'CHECK_USER_PRIVATE',
                'Authorization': 'Bearer ' + dataPhone.AUTH_TOKEN,
                'Content-Type': 'application/json'
            },
            body: this.encryptString(JSON.stringify({
                user: phone,
                msgType: "CHECK_USER_PRIVATE",
                cmdId: times + "000000",
                lang: "vi",
                time: times,
                channel: "APP",
                appVer: process.env.appVer,
                appCode: process.env.appCode,
                deviceOS: dataDevice.deviceOS,
                buildNumber: 1916,
                appId: "vn.momo.transfer",
                result: true,
                errorCode: 0,
                errorDesc: "",
                momoMsg:
                {
                    _class: "mservice.backend.entity.msg.LoginMsg",
                    getMutualFriend: false
                },
                extra:
                {
                    CHECK_INFO_NUMBER: receiver,
                    checkSum: this.checkSum(phone, "CHECK_USER_PRIVATE", times, dataPhone.setupKey)
                }
            }), key)
        };

        return new Promise((resolve, reject) => {
            request(options, async (err, response, body) => {
                try {
                    body = JSON.parse(this.decryptString(body, key));
                    return body.result ? resolve({
                        success: true,
                        message: 'Lấy thành công!',
                        name: body.extra.NAME
                    }) : resolve({
                        success: false,
                        message: body.errorDesc
                    })
                } catch (err) {
                    return resolve({
                        success: false,
                        message: 'Có lỗi xảy ra ' + err.message || err
                    })
                }
            })
        })
    } catch (err) {
        await momoModel.findOneAndUpdate({ phone }, { $set: { description: 'CHECK_USER_PRIVATE| Có lỗi xảy ra ' + err.message || err } })
        return ({
            success: false,
            message: 'Có lỗi xảy ra ' + err.message || err
        })
    }
}

exports.M2MU_INIT = async (phone, dataTransfer) => {
    try {
        const times = new Date().getTime();
        const checkSession = await this.checkSession(phone);

        if (!checkSession.success) {
            return checkSession;
        }

        const dataPhone = checkSession.data;
        const checkName = await this.checkName(phone, dataTransfer.phone);

        if (!checkName.success) {
            return checkName;
        }

        const dataDevice = dataPhone.dataDevice;
        let key = crypto.randomBytes(32).toString("hex").substring(32), requestkey = this.encryptRSA(key, dataPhone.REQUEST_ENCRYPT_KEY);
        let options = {
            method: 'POST',
            url: 'https://owa.momo.vn/api/',
            headers: {
                'msgtype': 'M2MU_INIT',
                'requestkey': requestkey,
                'userid': phone,
                'Authorization': 'Bearer ' + dataPhone.AUTH_TOKEN,
                'Content-Type': 'application/json'
            },
            body: this.encryptString(JSON.stringify({
                user: phone,
                msgType: "M2MU_INIT",
                cmdId: times + "000000",
                lang: "vi",
                time: times,
                channel: "APP",
                appVer: process.env.appVer,
                appCode: process.env.appCode,
                deviceOS: dataDevice.deviceOS,
                buildNumber: 0,
                appId: "vn.momo.platform",
                result: true,
                errorCode: 0,
                errorDesc: "",
                momoMsg: {
                    clientTime: times - 221,
                    tranType: 2018,
                    comment: dataTransfer.comment,
                    amount: dataTransfer.amount,
                    partnerId: dataTransfer.phone,
                    partnerName: checkName.name,
                    ref: "",
                    serviceCode: "transfer_p2p",
                    serviceId: "transfer_p2p",
                    _class: "mservice.backend.entity.msg.M2MUInitMsg",
                    tranList: [
                        {
                            partnerName: checkName.name,
                            partnerId: dataTransfer.phone,
                            originalAmount: dataTransfer.amount,
                            serviceCode: "transfer_p2p",
                            stickers: "",
                            themeBackground: "#f5fff6",
                            themeUrl: "https://cdn.mservice.com.vn/app/img/transfer/theme/Muasam-750x260.png",
                            transferSource: "",
                            socialUserId: "",
                            receiverType: 1,
                            _class: "mservice.backend.entity.msg.M2MUInitMsg",
                            tranType: 2018,
                            comment: dataTransfer.comment,
                            moneySource: 1,
                            partnerCode: "momo",
                            serviceMode: "transfer_p2p",
                            serviceId: "transfer_p2p",
                            extras: '{"loanId":0,"appSendChat":false,"loanIds":[],"stickers":"","themeUrl":"https://cdn.mservice.com.vn/app/img/transfer/theme/Muasam-750x260.png","themeP2P":"default","contactName":"","vpc_CardType":"SML","vpc_TicketNo":"","vpc_PaymentGateway":"","bankCustomerId":""}'
                        }
                    ],
                    extras: '{"loanId":0,"appSendChat":false,"loanIds":[],"stickers":"","themeUrl":"https://cdn.mservice.com.vn/app/img/transfer/theme/Muasam-750x260.png","themeP2P":"default","contactName":"","vpc_CardType":"SML","vpc_TicketNo":"","vpc_PaymentGateway":"","bankCustomerId":""}',
                    moneySource: 1,
                    defaultMoneySource: 1,
                    partnerCode: "momo",
                    rowCardId: "",
                    giftId: "",
                    useVoucher: 0,
                    prepaidIds: "",
                    usePrepaid: 0
                },
                extra: {
                    checkSum: this.checkSum(phone, "M2MU_INIT", times, dataPhone.setupKey)
                }
            }), key)
        };

        return new Promise((resolve, reject) => {
            request(options, async (err, response, body) => {
                try {
                    body = JSON.parse(this.decryptString(body, key));
                    return !body.result ? resolve({
                        success: false,
                        message: body.errorDesc
                    }) : resolve({
                        success: true,
                        message: 'Tạo lệnh chuyển tiền thành công!',
                        data: {
                            ids: body.momoMsg.replyMsgs[0].id,
                            tranHisMsg: body.momoMsg.replyMsgs[0].tranHisMsg,
                        }
                    })
                } catch (error) {
                    console.log(error);
                    await momoModel.findOneAndUpdate({ phone }, { $set: { description: 'M2MU_INIT| Có lỗi xảy ra ' + err || error } })
                    return resolve({
                        success: false,
                        message: 'Có lỗi xảy ra ' + err || error
                    });
                }
            })
        })
    } catch (err) {
        await momoModel.findOneAndUpdate({ phone }, { $set: { description: 'M2MU_INIT| Có lỗi xảy ra ' + err.message || err } })
        return ({
            success: false,
            message: 'Có lỗi xảy ra ' + err.message || err
        })
    }
}

exports.moneyTransfer = async (phone, dataTransfer) => {
    try {
        // phone, amount, comment
        console.log(dataTransfer);
        const times = new Date().getTime();
        const checkSession = await this.checkSession(phone);

        if (!checkSession.success) {
            return checkSession;
        }

        const dataPhone = checkSession.data;
        const dataDevice = dataPhone.dataDevice;
        const checkBalance = await this.getBalance(phone);
        console.log(checkBalance);

        if (!checkBalance.success) {
            return checkBalance;
        }

        if (checkBalance.balance < dataTransfer.amount) {
            return ({
                success: false,
                message: `Số dư ${phone} không đủ ${Intl.NumberFormat('en-US').format(dataTransfer.amount)}đ để chuyển khoản!`
            })
        }

        const init = await this.M2MU_INIT(phone, dataTransfer);

        if (!init.success) {
            return init;
        }

        let key = crypto.randomBytes(32).toString("hex").substring(32), requestkey = this.encryptRSA(key, dataPhone.REQUEST_ENCRYPT_KEY);
        let options = {
            method: 'POST',
            url: 'https://owa.momo.vn/api/',
            headers: {
                'requestkey': requestkey,
                'userid': phone,
                'Authorization': 'Bearer ' + dataPhone.AUTH_TOKEN,
                'Content-Type': 'application/json'
            },
            body: this.encryptString(JSON.stringify({
                user: phone,
                msgType: "M2MU_CONFIRM",
                pass: dataPhone.password,
                cmdId: times + "000000",
                lang: "vi",
                time: times,
                channel: "APP",
                appVer: process.env.appVer,
                appCode: process.env.appCode,
                deviceOS: dataDevice.deviceOS,
                buildNumber: 0,
                appId: "vn.momo.platform",
                result: true,
                errorCode: 0,
                errorDesc: "",
                momoMsg: {
                    otpType: "NA",
                    ipAddress: "N/A",
                    enableOptions: {
                        voucher: true,
                        discount: true,
                        prepaid: true,
                        desc: ""
                    },
                    _class: "mservice.backend.entity.msg.M2MUConfirmMsg",
                    quantity: 1,
                    idFirstReplyMsg: init.data.ids,
                    moneySource: 1,
                    cbAmount: 0,
                    tranHisMsg: init.data.tranHisMsg,
                    desc: "Thành công",
                    error: 0,
                    tranType: 2018,
                    ids: [init.data.ids],
                    amount: dataTransfer.amount,
                    originalAmount: dataTransfer.amount,
                    fee: 0,
                    feeCashIn: 0,
                    feeMoMo: 0,
                    cashInAmount: dataTransfer.amount,
                    otp: "",
                    extras: "{}"
                },
                extra: {
                    checkSum: this.checkSum(phone, "M2MU_CONFIRM", times, dataPhone.setupKey)
                }
            }), key)
        };

        return new Promise((resolve, reject) => {
            request(options, async (err, response, body) => {
                try {
                    body = JSON.parse(this.decryptString(body, key));
                    if (!body.result) {
                        resolve({
                            success: false,
                            message: body.errorDesc
                        })
                    } else {
                        await momoModel.findOneAndUpdate({ phone }, { amount: body.extra.BALANCE });
                        await new transferModel({ transId: body.momoMsg.replyMsgs[0].transId, phone, receiver: dataTransfer.phone, firstMoney: checkBalance.balance, lastMoney: body.extra.BALANCE, amount: dataTransfer.amount, comment: dataTransfer.comment }).save();

                        resolve({
                            success: true,
                            message: 'Chuyển tiền thành công!',
                            data: {
                                transId: body.momoMsg.replyMsgs[0].transId,
                                phone,
                                firstMoney: checkBalance.balance,
                                lastMoney: parseInt(body.extra.BALANCE),
                                dataTransfer,
                            }
                        })
                    }
                } catch (err) {
                    console.log(err);
                    await momoModel.findOneAndUpdate({ phone }, { $set: { description: 'M2MU_CONFIRM| Có lỗi xảy ra ' + err.message || err } })

                    return resolve({
                        success: false,
                        message: 'Có lỗi xảy ra ' + err.message || err
                    });
                }
            })
        })
    } catch (err) {
        await momoModel.findOneAndUpdate({ phone }, { $set: { description: 'M2MU_CONFIRM| Có lỗi xảy ra ' + err.message || err } })
        return ({
            success: false,
            message: 'Có lỗi xảy ra ' + err.message || err
        })
    }
}x
