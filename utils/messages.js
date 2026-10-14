export const getLang = (req, user) => {
  const rawLang = req?.body?.lang || req?.query?.lang || req?.headers?.['x-lang'] || req?.headers?.['accept-language'] || user?.lang || 'en';
  return String(rawLang).toLowerCase().includes('ar') ? 'ar' : 'en';
};

export const messages = {
  requiredFields: {
    ar: "يرجى التأكد من إدخال جميع المعلومات المطلوبة.",
    en: "Please verify that all required information is entered."
  },
  captchaRequired: {
    ar: "يرجى تأكيد اختبار الكابتشا لإتمام عملية التسجيل.",
    en: "Please verify that you are not a robot to complete registration."
  },
  forgedCaptcha: {
    ar: "تم حظر جهازك وبريدك الإلكتروني بشكل دائم بسبب نشاط مشبوه.",
    en: "Your device and email have been permanently banned due to suspicious activity."
  },
  devicePermanentBan: {
    ar: "جهازك محظور بشكل دائم من القيام بأي نشاط على المنصة.",
    en: "Your device is permanently banned from performing any activity."
  },
  emailPermanentBan: {
    ar: "هذا البريد الإلكتروني محظور بشكل دائم عبر المنصة على جميع الأجهزة.",
    en: "This email is permanently banned across the platform on all devices."
  },
  accountPermanentBan: {
    ar: "أنت محظور بشكل دائم على هذا الجهاز.",
    en: "You are permanently banned on this device."
  },
  accountTempSuspension: {
    ar: "هذا الحساب معلق مؤقتاً؛ يرجى الانتظار حتى انتهاء فترة التعليق.",
    en: "This account is temporarily suspended; please wait until the suspension period ends."
  },
  accountDeletedAttemptLimit: {
    ar: "لا يمكن حذف هذا الحساب بسبب استنفاد محاولات الدخول.",
    en: "This account cannot be deleted due to the exhaustion of login attempts."
  },
  accountBanned: {
    ar: "هذا الحساب محظور حالياً.",
    en: "This account is banned."
  },
  accountNotFound: {
    ar: "هذا الحساب غير موجود.",
    en: "This account does not exist."
  },
  alreadyVerified: {
    ar: "هذا الحساب موجود بالفعل.",
    en: "This account already exists."
  },
  accountAlreadyExists: {
    ar: "هذا الحساب موجود بالفعل.",
    en: "This account already exists."
  },
  emailAlreadyExists: {
    ar: "البريد الإلكتروني مسجل بالفعل.",
    en: "This email is already registered."
  },
  usernameAlreadyExists: {
    ar: "اسم المستخدم هذا مستخدم بالفعل. يرجى اختيار اسم مستخدم آخر.",
    en: "This username is already taken. Please choose another username."
  },
  emailMismatch: {
    ar: "تنبيه أمني: البريد الإلكتروني المدخل لا يتطابق مع الحساب.",
    en: "Security alert: The entered email does not match the account."
  },
  accountActive: {
    ar: "فشلت العملية: هذا الحساب نشط حالياً.",
    en: "Process failed: this account is currently active."
  },
  codeIncorrect: {
    ar: "رمز التحقق غير صحيح. يرجى التأكد من الرمز المرسل إلى بريدك الإلكتروني.",
    en: "This code is incorrect. Please verify the code sent to this email."
  },
  codeDeviceMismatch: {
    ar: "هذا الرمز غير صالح لهذا الجهاز.",
    en: "This code is not valid for this device."
  },
  deviceIdRequired: {
    ar: "تنبيه أمني: معرف الجهاز (Device ID) مطلوب.",
    en: "Security alert: Device ID is required."
  },
  deviceMismatch: {
    ar: "تنبيه أمني: تم استخدام الرمز من جهاز غير مصرح به.",
    en: "Security alert: Token used from unauthorized device."
  },
  deviceDbMismatch: {
    ar: "تنبيه أمني: الجهاز لا يطابق جهاز الحساب المسجل.",
    en: "Security alert: Device does not match registered account device."
  },
  tokenMissing: {
    ar: "رمز التحقق (Verification Token) مفقود.",
    en: "Verification token missing."
  },
  tokenInvalid: {
    ar: "رمز التحقق غير صالح أو منتهي الصلاحية.",
    en: "Invalid or expired verification token."
  },
  tokenTypeInvalid: {
    ar: "نوع رمز التحقق غير صالح.",
    en: "Invalid verification token type."
  },
  tokenUserMismatch: {
    ar: "تنبيه أمني: رمز التحقق لا يتطابق مع المستخدم المطلوب.",
    en: "Security alert: Token does not match requested user."
  },
  resendLimitExceeded: {
    ar: "لقد تجاوزت الحد المسموح به (5 طلبات كل 5 دقائق). تم منعك من إرسال أي طلب آخر لمدة 10 دقائق.",
    en: "You have exceeded the allowed limit (5 requests per 5 minutes). You are blocked from sending any requests for 10 minutes."
  },
  resendSuccess: {
    ar: "تم إعادة إرسال رمز التحقق بنجاح إلى بريدك الإلكتروني.",
    en: "Verification code has been successfully resent to your email."
  },
  signupSuccess: {
    ar: "تم إنشاء الحساب بنجاح وإرسال رمز التحقق.",
    en: "User created successfully and verification code sent."
  },
  verifySuccess: {
    ar: "تم التحقق وتسجيل الدخول بنجاح.",
    en: "Verification completed and signed in successfully."
  },
  loginSuccess: {
    ar: "تم تسجيل الدخول بنجاح.",
    en: "Signed in successfully."
  },
  invalidCredentials: {
    ar: "بيانات الدخول غير صحيحة. يرجى التأكد من البريد وكلمة المرور.",
    en: "Invalid credentials. Please check your email and password."
  },
  userDeletedSuccess: {
    ar: "تم حذف الحساب بنجاح.",
    en: "User deleted successfully."
  },
  stateUpdatedSuccess: {
    ar: "تم تحديث حالة التحقق بنجاح.",
    en: "Verification state updated successfully."
  },
  serviceSuccess: {
    ar: "تم استلام طلب الخدمة الخاص بك بنجاح.",
    en: "Your service request has been submitted successfully."
  },
  invalidJson: {
    ar: "البيانات المرسلة غير صالحة بصيغة JSON. يرجى التحقق من صياغة الطلب.",
    en: "Data sent is not valid JSON. Please check the request body formatting."
  },
  serverError: {
    ar: "حدث خطأ في الخادم أثناء معالجة الطلب.",
    en: "A server error occurred while processing the request."
  }
};

export const getMsg = (key, req, user) => {
  const lang = getLang(req, user);
  const entry = messages[key];
  if (!entry) return key;
  return entry[lang] || entry['en'] || key;
};

export const getResendLockMsg = (remainingMinutes, req, user) => {
  const lang = getLang(req, user);
  if (lang === 'ar') {
    return `لقد تجاوزت الحد الأقصى لطلبات إعادة الإرسال (5 محاولات). تم منعك من إرسال أي طلب آخر لمدة 10 دقائق. يرجى الانتظار ${remainingMinutes} دقيقة.`;
  }
  return `You have exceeded the maximum resend requests (5 attempts). You are blocked from sending requests for 10 minutes. Please wait ${remainingMinutes} minute(s).`;
};

export const getEmailSendErrorMsg = (details, req, user) => {
  const lang = getLang(req, user);
  if (lang === 'ar') {
    return `حدث خطأ أثناء إرسال البريد الإلكتروني: ${details || 'يرجى المحاولة لاحقاً'}`;
  }
  return `Error sending email: ${details || 'Please try again later'}`;
};
