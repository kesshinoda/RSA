import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class RSA
{
    private static void keyGenerator()
    {
        Random rnd = new Random();

        BigInteger p;
        BigInteger q;
        BigInteger de;
        BigInteger ee;
        BigInteger n;

        String fileName = "keys.txt";

        PrintWriter outputStream = null;
        try
        {
            outputStream = new PrintWriter(fileName);
        }
        catch(FileNotFoundException e)
        {
            System.out.println("Error opening the file name" +fileName);
            System.exit(0);
        }

        do {
            //Create two big prime numbers(1024 bits), p and q that are not same value.
            p = BigInteger.probablePrime(1024, rnd);
            q = BigInteger.probablePrime(1024, rnd);
        }while(p.compareTo(q) == 0);

        n = p.multiply(q); //Create a public key n such that n = p*q

        BigInteger n1 = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); //n1 = (p-1)*(q-1)

        do {
            //this is ciphertext c such that c = message^e (mod n)
            ee = new BigInteger(1024, rnd);
        }while(ee.compareTo(n1) != -1 || !ee.gcd(n1).equals(BigInteger.ONE));


        de = ee.modInverse(n1); //Create a private key which is e^(-1) (mod n1)

        outputStream.println("p = " + p);
        outputStream.println("q = " + q);
        outputStream.println("n = " + n);
        outputStream.println("e = " + ee);
        outputStream.println("d = " + de);

        outputStream.close();
        System.out.println("Your key has been written to " + fileName);
    }

    private static BigInteger encryptBlock(BigInteger message, BigInteger e, BigInteger n)
    {
        //Return ciphertext such that ciphertext = message^e (mod n)
        return message.modPow(e, n);
    }

    public static String[] encrypt(String message, BigInteger e, BigInteger n)
    {
        String[] cipherText;

        //Convert message to hex
        String hexMessage = "";
        for(int i = 0; i < message.length(); i++)
            hexMessage = hexMessage + Integer.toHexString(message.charAt(i));

        cipherText = new String[hexMessage.length() / 512 + 1];

        //Break hexMessage into blocks of less than 2048 bits (hex string of length 512)
        int i = 0;
        while(i < hexMessage.length())
        {
            int j = i / 512;
            cipherText[j] = "";
            String hexBlock;
            if (i+512 < hexMessage.length())
                hexBlock = hexMessage.substring(i, i+512);
            else
                hexBlock = hexMessage.substring(i);
            BigInteger messageBlock = new BigInteger(hexBlock, 16); //Convert hex string to BigInteger.
            cipherText[j] = encryptBlock(messageBlock, e, n).toString(16);
            i+=512;
        }

        return cipherText;
    }

    private static BigInteger decryptBlock(BigInteger encryptedMessage, BigInteger d, BigInteger n)
    {
        //Return original message such that original message = ciphertext^d (mod n)
        return encryptedMessage.modPow(d, n);
    }

    //Converts all the decrypted blocks back to ASCII text.
    public static String decrypt(String[] cipherText, BigInteger d, BigInteger n)
    {
        String message = "";
        for (int i = 0; i < cipherText.length; i++)
        {
            BigInteger encryptedBlock = new BigInteger(cipherText[i], 16);
            BigInteger messageBlock = decryptBlock(encryptedBlock, d, n);
            String hexBlock = messageBlock.toString(16);

            for (int j = 0; j < hexBlock.length(); j+=2)
            {
                String t = hexBlock.substring(j, j+2);
                message = message + (char) Integer.parseInt(t, 16);
            }
        }
        return message;
    }

    public static void main(String[] args)
    {
        Scanner keyboard = new Scanner(System.in);
        System.out.println("Would you like to generate keys? (y/n)");
        String response = keyboard.nextLine();
        if (response.charAt(0) == 'y')
        {
            keyGenerator();
            System.exit(0);
        }

        System.out.println("Enter a message:");
        String message = keyboard.nextLine();

        //Public key n
        BigInteger n = new BigInteger("19465293490332538369249590773029520347372202686338212462379104" +
                "8405017410619288640504812874243898221661038799761223687305843199843685557135216918348109" +
                "9944071513359779977201664780648309732457140240930080340243867922427115632174357240910451" +
                "3357492237031322479813443923370463827968123402020247376151172670772233987497154173464570" +
                "4746486299115016133841697065337038043573572996494279019178877281098017167715698282898377" +
                "0657484151904430643527345906015369812332897796289288493732775092028783691943799796292324" +
                "5845600581728300774061093782374931569243436034599979519962378763460052519706899551002059" +
                "844365702169112689051921421");

        //Public key e
        BigInteger e = new BigInteger("15473803429437931321869109980328735491248870908179952599522427" +
                "9737686135150370602044680289545451372862818226221981135319545601008571850405682351696249" +
                "5723815043245507175613567491227043466596666865574361323902071125692087787631572796575385" +
                "34618858767067263614793920007242327143869246862203133662022804746009709");

        //Private key d
        BigInteger d = new BigInteger("17750484948723392841745062953130800910397961444014828885170044" +
                "4222782171049464249659463029501826080572308426689741809092548544756022036069679230632262" +
                "2926151186539125834556526704692516067550916223820745530880596993232466526497794535400909" +
                "9290394292223468672610096371779871014778049542511845995119849093523306034678888644114577" +
                "1902544015346175239074363351766021283515333136447275954892835079572195098477315093070903" +
                "2971990251144366570268105091109991895660846155686818645828445479750580732589794027885128" +
                "0746945654723318568829581743663201516370555250056430706147863602723575498661794784017556" +
                "288919710639453879794899689");

        //The loop below encrypts a message and prints out each encrypted block.
        String[] cipherText = encrypt(message, e, n);
        for (int i = 0; i < cipherText.length; i++)
        {
            System.out.println("Block " + i + ": " + cipherText[i]);
        }

        //Print out the decrypted message
        System.out.println(decrypt(cipherText, d, n));
    }
}
