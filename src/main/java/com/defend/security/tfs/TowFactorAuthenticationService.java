package com.defend.security.tfs;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import lombok.extern.slf4j.Slf4j;

import org.springframework.stereotype.Service;

import static dev.samstevens.totp.util.Utils.getDataUriForImage;

@Service
@Slf4j
public class TowFactorAuthenticationService {

    public String generateNewSecret()
    {
        return new DefaultSecretGenerator().generate();
    }

    public String generateQrCodeImageUri(String secret)
    {

        QrData data = new QrData.Builder()
                .label("example@example.com")
                .secret(secret)
                .issuer("AppName")
                .algorithm(HashingAlgorithm.SHA1) // More on this below
                .digits(6)
                .period(30)
                .build();
        QrGenerator generator =new ZxingPngQrGenerator();
        byte[] imageData = new byte[8];
        try
        {
            imageData = generator.generate(data);

        } catch (QrGenerationException e) {
            e.printStackTrace();
            log.error("error while generating qrcode");
            throw new RuntimeException(e);
        }
        return getDataUriForImage(imageData , generator.getImageMimeType());
    }
//validation for the one time password
    public boolean isOtpValid(String secret ,String code)
    {
        TimeProvider timeProvider = new SystemTimeProvider();
        CodeGenerator codeGenerator = new DefaultCodeGenerator();
        CodeVerifier codeVerifier = new DefaultCodeVerifier(codeGenerator , timeProvider);

        return codeVerifier.isValidCode(secret , code);

    }

    public boolean isOtpNotValid(String secret ,String code){
        return !this.isOtpValid(secret, code);
    }

}
