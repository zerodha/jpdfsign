import com.itextpdf.text.pdf.PdfReader;
import com.itextpdf.text.pdf.PdfStamper;
import com.itextpdf.text.pdf.PdfSignatureAppearance;

import com.itextpdf.text.pdf.security.ExternalDigest;
import com.itextpdf.text.pdf.security.BouncyCastleDigest;
import com.itextpdf.text.pdf.security.ExternalSignature;
import com.itextpdf.text.pdf.security.PrivateKeySignature;
import com.itextpdf.text.pdf.security.DigestAlgorithms;
import com.itextpdf.text.pdf.security.MakeSignature;
import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;
import com.itextpdf.text.Rectangle;
import com.itextpdf.text.BaseColor;
import com.itextpdf.text.Font;
import com.itextpdf.text.Font.FontFamily;
import com.itextpdf.text.pdf.PdfWriter;
import com.itextpdf.text.DocumentException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.cert.Certificate;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.io.FileOutputStream;
import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;
import java.util.ArrayList;

import java.io.FileReader;
import java.util.Iterator;
import java.util.Map;

public class PdfSigner {
    public void sign(String src, String dest, String password,
        Certificate[] chain,
        ExternalDigest digest,
        ExternalSignature signature,
        CryptoStandard subfilter,
        String reason,
        String contact,
        String location,
        Rectangle rect,
        Font font,
        int page) throws GeneralSecurityException, IOException, DocumentException {

        // Creating the reader and the stamper
        PdfReader reader;
        try {
            reader = new PdfReader(src);
        } catch (Exception e) {
            return;
        }

        FileOutputStream os;
        try {
            os = new FileOutputStream(dest);
        } catch (Exception e) {
            return;
        }

        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0');

        /** User password. */
        byte[] USER = password.getBytes();
        /** Owner password. */
        byte[] OWNER = password.getBytes();
        stamper.setEncryption(USER, OWNER, PdfWriter.ALLOW_PRINTING, PdfWriter.ENCRYPTION_AES_128 | PdfWriter.DO_NOT_ENCRYPT_METADATA);

        // Creating the appearance
        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();
        appearance.setReason(reason);
        appearance.setContact(contact);
        appearance.setLocation(location);

        appearance.setVisibleSignature(rect, page, null);
        appearance.setLayer2Font(font);

        // Creating the signature
        MakeSignature.signDetached(appearance, digest, signature, chain,
            null, null, null, 0, subfilter);
    }

    // get the pdf conversion file list
    private ArrayList getListFromFile(String infile) throws IOException {
        ArrayList < String[] > list = new ArrayList < String[] > ();

        BufferedReader br = new BufferedReader(new FileReader(new File(infile)));

        String line = null;
        while ((line = br.readLine()) != null) {
            String[] ch = line.trim().split(" ");
            if (ch.length == 2) {
                list.add(ch);
            }
        }

        br.close();

        return list;
    }

    // get list of pdfs to convert from a given directory
    private ArrayList getListFromDirectory(String source, String target) throws IOException {
        ArrayList < String[] > list = new ArrayList < String[] > ();

        File folder = new File(source);
        File[] files = folder.listFiles();

        for (int i = 0; i < files.length; i++) {
            // System.out.println(files[i].getName());
            String[] split_data = files[i].getName().split("_");
            // System.out.println(split_data[0] + " --- " + split_data[1]);
            String fname = files[i].getPath();
            if (files[i].isFile() && fname.toLowerCase().endsWith(".pdf")) {
                String[] ch = new String[] {
                    fname,
                    target + "/" + split_data[1],
                    split_data[0]
                };
                list.add(ch);
            }
        }

        return list;
    }

    public static void main(String[] args) throws GeneralSecurityException, IOException, DocumentException {
        if (args.length < 1) {
            System.out.println("Contract notes PDF signer for Zerodha\n\n1) PdfSigner file_list.txt");
            System.out.println("The file list should have one entry per line and each entry should be: input.pdf output.pdf");
            System.out.println("2) PdfSigner input_dir output_dir");
            System.exit(0);
        }

        // Load the config.
        FileInputStream inp = new FileInputStream("config.ini");
        Properties config = new Properties();
        config.load(inp);

        PdfSigner app = new PdfSigner();

        // Load file list from an input list or from an input directory
        ArrayList < String[] > flist;
        if (args.length == 2) {
            if (args[0].equals(args[1])) {
                System.out.println("Can't read and write from the same directory");
                System.exit(0);
            }
            flist = app.getListFromDirectory(args[0], args[1]);
        } else {
            flist = app.getListFromFile(args[0]);
        }

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance("pkcs12");
        ks.load(new FileInputStream(config.getProperty("keyfile")), config.getProperty("password").toCharArray());

        String alias = (String) ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, config.getProperty("password").toCharArray());
        Certificate[] chain = ks.getCertificateChain(alias);

        ExternalDigest digest = new BouncyCastleDigest();
        ExternalSignature signature = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, provider.getName());

        Font font = new Font(FontFamily.HELVETICA, 9);
        font.setColor(16, 181, 60);
        font.setStyle("bold");


        // Properties from the config file
        String reason = config.getProperty("reason"),
            contact = config.getProperty("contact"),
            location = config.getProperty("location");

        int[] coords = new int[] {
            Integer.parseInt(config.getProperty("x1")),
                Integer.parseInt(config.getProperty("y1")),
                Integer.parseInt(config.getProperty("x2")),
                Integer.parseInt(config.getProperty("y2"))
        };
        Rectangle rect = new Rectangle(coords[0], coords[1], coords[2], coords[3]);

        int page = Integer.parseInt(config.getProperty("page"));

        System.out.println("Signing " + flist.size() + " files");
        // Run through and sign each file
        for (int i = 0; i < flist.size(); i++) {
            String[] fl = flist.get(i);
            app.sign(fl[0],
                String.format(fl[1], 1),
                String.format(fl[2], 1),
                chain,
                digest,
                signature,
                CryptoStandard.CMS,
                reason,
                contact,
                location,
                rect,
                font,
                page
            );

            if ((i + 1) % 100 == 0) {
                System.out.println(i);
            }
        }

        System.out.println("Done");
    }
}