package kodrat.keycloak.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.EncodeHintType;
import com.google.zxing.qrcode.QRCodeWriter;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Base64;
import java.util.EnumMap;
import java.util.Map;
import kodrat.keycloak.exception.SSIException;

/**
 * Service for generating QR codes for SSI authentication invitations.
 *
 * <p>This service generates QR codes that encode DIDComm invitations or
 * OpenID4VP authorization URLs for wallet scanning. QR codes are generated
 * locally using the ZXing library with fallback to an external API if
 * local generation fails.
 *
 * <h2>QR Code Specifications</h2>
 * <table border="1">
 *   <caption>QR Code Settings</caption>
 *   <tr><th>Property</th><th>Value</th></tr>
 *   <tr><td>Size</td><td>220x220 pixels</td></tr>
 *   <tr><td>Error Correction</td><td>Level M (~15% recovery)</td></tr>
 *   <tr><td>Character Set</td><td>UTF-8</td></tr>
 *   <tr><td>Margin</td><td>1 module</td></tr>
 *   <tr><td>Format</td><td>PNG</td></tr>
 * </table>
 *
 * <h2>Output Formats</h2>
 * <p>Two output formats are supported:
 * <ul>
 *   <li><strong>Data URL:</strong> Base64-encoded PNG with data URI scheme
 *       ({@code data:image/png;base64,...})</li>
 *   <li><strong>PNG bytes:</strong> Raw PNG byte array for HTTP responses</li>
 * </ul>
 *
 * <h2>Usage Examples</h2>
 * <pre>{@code
 * // Generate data URL for embedding in HTML
 * String dataUrl = QRCodeService.generateQRCodeUrl(invitationUrl);
 * model.addAttribute("qrCode", dataUrl);
 * 
 * // Generate PNG for HTTP response
 * byte[] png = QRCodeService.generateQRCodePng(invitationUrl);
 * return Response.ok(png, "image/png").build();
 * }</pre>
 *
 * <h2>Error Handling</h2>
 * <p>If local QR code generation fails, the service falls back to an external
 * API (qrserver.com). If both fail, an {@link SSIException} is thrown.
 *
 * <h2>Thread Safety</h2>
 * <p>This class is stateless and all methods are static. It is safe to call from
 * multiple threads concurrently.
 *
 * @see MyResourceProvider#qrCode(String)
 * @since 1.0.0
 * @author Kodrat Development Team
 */
public final class QRCodeService {

    private static final String QR_API_URL = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=";
    
    private static final int QR_SIZE = 220;

    /**
     * Private constructor to prevent instantiation.
     * This is a utility class with only static methods.
     *
     * @throws AssertionError always, as this constructor should never be called
     */
    private QRCodeService() {
        throw new AssertionError("Utility class cannot be instantiated");
    }

    /**
     * Generates a QR code as a data URL containing the specified data.
     *
     * <p>The returned data URL can be used directly in HTML img src attributes:
     * <pre>{@code
     * <img src="${qrCode}" alt="Scan with wallet" />
     * }</pre>
     *
     * <p>If local generation fails, falls back to an external QR code API.
     *
     * @param data the data to encode in the QR code (e.g., invitation URL)
     * @return a data URL string ({@code data:image/png;base64,...})
     * @throws SSIException if the data is empty or encoding fails
     */
    public static String generateQRCodeUrl(String data) {
        if (data == null || data.isBlank()) {
            throw new SSIException("QR code data is empty");
        }

        try {
            String base64 = Base64.getEncoder().encodeToString(generateQRCodePng(data));
            return "data:image/png;base64," + base64;
        } catch (Exception e) {
            try {
                String encodedData = URLEncoder.encode(data, "UTF-8");
                return QR_API_URL + encodedData;
            } catch (UnsupportedEncodingException ex) {
                throw new SSIException("Failed to encode QR code data", ex);
            }
        }
    }

    /**
     * Generates a QR code as a PNG byte array.
     *
     * <p>This method generates the QR code locally using the ZXing library.
     * The output is suitable for HTTP responses with Content-Type: image/png.
     *
     * <h3>QR Code Settings</h3>
     * <ul>
     *   <li>Size: 220x220 pixels</li>
     *   <li>Error Correction: Level M (~15% data recovery)</li>
     *   <li>Character Set: UTF-8</li>
     *   <li>Margin: 1 module</li>
     * </ul>
     *
     * @param data the data to encode in the QR code
     * @return a byte array containing the PNG image data
     * @throws SSIException if the data is empty or generation fails
     */
    public static byte[] generateQRCodePng(String data) {
        if (data == null || data.isBlank()) {
            throw new SSIException("QR code data is empty");
        }

        try {
            Map<EncodeHintType, Object> hints = new EnumMap<>(EncodeHintType.class);
            hints.put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.M);
            hints.put(EncodeHintType.CHARACTER_SET, "UTF-8");
            hints.put(EncodeHintType.MARGIN, 1);

            BitMatrix matrix = new QRCodeWriter().encode(data, BarcodeFormat.QR_CODE, QR_SIZE, QR_SIZE, hints);
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(matrix, "PNG", output);
            return output.toByteArray();
        } catch (Exception e) {
            throw new SSIException("Failed to generate QR code PNG", e);
        }
    }
}
