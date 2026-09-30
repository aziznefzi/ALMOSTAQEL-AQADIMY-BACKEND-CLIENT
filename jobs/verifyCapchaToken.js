import axios from "axios"

export const verifyCaptchaToken = async (token) => {
    try {
        const secretKey = process.env.RECAPTION_SECRET_KEY;
        const response = await axios.post(`https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${token}`);
        return response.data.success; 
    } catch (error) {
        console.error("Error connecting to Google reCAPTCHA:", error?.response?.data?.message);
        return false;
    }
};