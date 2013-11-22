import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;

/**
 * AES-128 implementation using GF2
 * 
 * @author Ryan Kasprzyk
 */
public class AES {
    public static ArrayList<Integer> mX = new ArrayList<>();
    public static int prime = 2;
    public static int[][] subMat = {
        makePoly(hexToBin("8f")),
        makePoly(hexToBin("c7")),
        makePoly(hexToBin("e3")),
        makePoly(hexToBin("f1")),
        makePoly(hexToBin("f8")),
        makePoly(hexToBin("7c")),
        makePoly(hexToBin("3e")),
        makePoly(hexToBin("1f"))};
    public static int[] subCol = makePoly(hexToBin("c6"));
    public static int[][] invSubMat = {
        makePoly(hexToBin("25")),
        makePoly(hexToBin("92")),
        makePoly(hexToBin("49")),
        makePoly(hexToBin("a4")),
        makePoly(hexToBin("52")),
        makePoly(hexToBin("29")),
        makePoly(hexToBin("94")),
        makePoly(hexToBin("4a"))};
    public static int[] invSubCol = {1, 0, 1, 0, 0, 0, 0, 0};
    public static String[][] mixCols = {
        {"02", "03", "01", "01"},
        {"01", "02", "03", "01"},
        {"01", "01", "02", "03"},
        {"03", "01", "01", "02"}};
    public static String[][] invMixCols = {
        {"0e", "0b", "0d", "09"},
        {"09", "0e", "0b", "0d"},
        {"0d", "09", "0e", "0b"},
        {"0b", "0d", "09", "0e"}};

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws FileNotFoundException, IOException {
        String key;
        String plain;
        String cipher;
        try (BufferedReader in = new BufferedReader(new FileReader("input.txt"))) {
            String[] poly = in.readLine().split(" ");
            for(int i = 0; i < poly.length; i++){
                mX.add(Integer.parseInt(poly[i]));
            }
            key = in.readLine();
            plain = in.readLine();
            cipher = in.readLine();
        }
        try (BufferedWriter out = new BufferedWriter(new FileWriter("output.txt"))) {
            ArrayList<String[][]> keySched = new ArrayList<>();
            String[][] newState = toState(plain);
            String[][] keyState = toState(key);
            newState = encrypt(newState, keyState);
            System.out.println(toStream(newState));
            out.write(toStream(newState));
            out.newLine();
            newState = decrypt(newState, keyState);
            System.out.println(toStream(newState));
            out.write(toStream(newState));
        }
    }
    
    public static String[][] encrypt(String[][] p, String[][]k){
        String[][]ky = k;
        String[][]c = p;
        
        ArrayList<String[][]> keySched = keySchedule(ky);
        c = addRoundKey(keySched.get(0), c);
        
        for(int i = 1; i < 10; i++){
            c = subBytes(c);
            c = shiftRows(c);
            c = mixColumns(c);
            c = addRoundKey(keySched.get(i), c);
        }
        
        c = subBytes(c);
        c = shiftRows(c);
        c = addRoundKey(keySched.get(10), c);
        return c;
    }
    
    public static String[][] decrypt(String[][]c, String[][]k){
        String[][] ky = k;
        String[][] p = c;
        
        ArrayList<String[][]> keySched = keySchedule(ky);
        p = addRoundKey(keySched.get(10), p);
        
        for(int i = 9; i > 0; i--){
            p = invShiftRows(p);
            p = invSubBytes(p);
            p = addRoundKey(keySched.get(i), p);
            p = invMixColumns(p);
        }
        
        p = invShiftRows(p);
        p = invSubBytes(p);
        p = addRoundKey(keySched.get(0), p);
        return p;
    }

    /**
     * AddRoundKey
     * @param key
     * @param state
     * @return 
     */
    public static String[][] addRoundKey(String[][] key, String[][] state) {
        String[][] newState = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int result = Integer.parseInt(key[i][j], 16) ^ Integer.parseInt(state[i][j], 16);
                newState[i][j] = decToHex(result);
            }
        }
        return newState;
    }

    /**
     * SubBytes function
     * @param state
     * @return 
     */
    public static String[][] subBytes(String[][] state) {
        String[][] newState = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                newState[i][j] = sBox(state[i][j]);
            }
        }
        return newState;
    }

    /**
     * S-Box function
     * @param entry
     * @return 
     */
    public static String sBox(String entry) {
        int[] ePoly;
        if (Integer.parseInt(entry, 16) == 0) {
            String out = hexToBin("00");
            ePoly = makePoly(out);
        } else {
            ePoly = makePoly(hexToBin(entry));
            ArrayList<Integer> p = new ArrayList<>();
            for (int i = 0; i < ePoly.length; i++) {
                p.add(ePoly[i]);
            }
            trimZeroes(p);
            p = EEAP(p, mX)[0];
            String bin = "";
            for (int i = 0; i < p.size(); i++) {
                bin += p.get(i);
            }
            ePoly = makePoly(hexToBin(binToHex(bin)));
        }
        ePoly = reverse(ePoly);
        int[] prod = new int[ePoly.length];
        for (int i = 0; i < ePoly.length; i++) {
            int sum = 0;
            for (int j = 0; j < ePoly.length; j++) {
                sum += ePoly[j] * subMat[i][j];
            }
            sum += subCol[i];
            sum %= 2;
            prod[i] = sum;
        }
        prod = reverse(prod);
        return binToHex(toString(prod));
    }
    
    /**
     * ShiftRows function
     * @param state
     * @return 
     */
    public static String[][] shiftRows(String[][] state){
        String[][] newState = new String[4][4];
        newState[0][0] = state[0][0];
        newState[0][1] = state[1][1];
        newState[0][2] = state[2][2];
        newState[0][3] = state[3][3];
        
        newState[1][0] = state[1][0];
        newState[1][1] = state[2][1];
        newState[1][2] = state[3][2];
        newState[1][3] = state[0][3];
        
        newState[2][0] = state[2][0];
        newState[2][1] = state[3][1];
        newState[2][2] = state[0][2];
        newState[2][3] = state[1][3];
        
        newState[3][0] = state[3][0];
        newState[3][1] = state[0][1];
        newState[3][2] = state[1][2];
        newState[3][3] = state[2][3];
        return newState;
    }

    /**
     * MixColumns function
     * @param state
     * @return 
     */
    public static String[][] mixColumns(String[][] state) {
        String[][] newState = new String[4][4];
        String[] column, res;
        ArrayList<Integer> result = new ArrayList<>();
        ArrayList<Integer> op;
        for (int k = 0; k < 4; k++) {
            column = state[k];
            res = new String[4];
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    op = multiply(makeAPoly(hexToBin(column[j])), makeAPoly(hexToBin(mixCols[i][j])));
                    result = add(op, result);
                }
                trimZeroes(result);
                result = PLDA(result, mX)[1];
                res[i] = binToHex(toString(result));
                result = new ArrayList<>();
            }
            newState[k] = res;
        }
        return newState;
    }

    /**
     * Inverse subBytes function
     * @param state
     * @return 
     */
    public static String[][] invSubBytes(String[][] state) {
        String[][] newState = new String[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                newState[i][j] = invSBox(state[i][j]);
            }
        }
        return newState;
    }

    /**
     * Inverse S-Box function
     * @param entry
     * @return 
     */
    public static String invSBox(String entry) {
        int[] ePoly = makePoly(hexToBin(entry));
        ePoly = reverse(ePoly);

        int[] prod = new int[ePoly.length];
        for (int i = 0; i < ePoly.length; i++) {
            int sum = 0;
            for (int j = 0; j < ePoly.length; j++) {
                sum += ePoly[j] * invSubMat[i][j];
            }
            sum += invSubCol[i];
            sum %= 2;
            prod[i] = sum;
        }
        prod = reverse(prod);
        entry = binToHex(toString(prod));

        if (Integer.parseInt(entry, 16) == 0) {
            String out = hexToBin("00");
            ePoly = makePoly(out);
        } else {
            ePoly = makePoly(hexToBin(entry));
            ArrayList<Integer> p = new ArrayList<>();
            for (int i = 0; i < ePoly.length; i++) {
                p.add(ePoly[i]);
            }
            trimZeroes(p);
            p = EEAP(p, mX)[0];
            String bin = "";
            for (int i = 0; i < p.size(); i++) {
                bin += p.get(i);
            }
            ePoly = makePoly(hexToBin(binToHex(bin)));
        }

        return binToHex(toString(ePoly));
    }

    /**
     * Inverse shiftRows function
     * @param state
     * @return 
     */
    public static String[][] invShiftRows(String[][] state) {
        String[][] newState = new String[4][4];
        newState[0][0] = state[0][0];
        newState[1][1] = state[0][1];
        newState[2][2] = state[0][2];
        newState[3][3] = state[0][3];
        
        newState[1][0] = state[1][0];
        newState[2][1] = state[1][1];
        newState[3][2] = state[1][2];
        newState[0][3] = state[1][3];
        
        newState[2][0] = state[2][0];
        newState[3][1] = state[2][1];
        newState[0][2] = state[2][2];
        newState[1][3] = state[2][3];
        
        newState[3][0] = state[3][0];
        newState[0][1] = state[3][1];
        newState[1][2] = state[3][2];
        newState[2][3] = state[3][3];
        return newState;
    }

    /**
     * Inverse mixColumns function
     * @param state
     * @return 
     */
    public static String[][] invMixColumns(String[][] state) {
        String[][] newState = new String[4][4];
        String[] column, res;
        ArrayList<Integer> result = new ArrayList<>();
        ArrayList<Integer> op;
        for (int k = 0; k < 4; k++) {
            column = state[k];
            res = new String[4];
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    op = multiply(makeAPoly(hexToBin(column[j])), makeAPoly(hexToBin(invMixCols[i][j])));
                    result = add(op, result);
                }
                trimZeroes(result);
                result = PLDA(result, mX)[1];
                res[i] = binToHex(toString(result));
                result = new ArrayList<>();
            }
            newState[k] = res;
        }
        return newState;
    }

    /**
     * Function g used by the keySchedule algorithm
     * @param lastWord
     * @param roundConst
     * @return 
     */
    public static String[] g(String[] lastWord, String roundConst) {
        String[] gWord = lastWord;
        String[] holder = new String[4];
        holder[0] = gWord[1];
        holder[1] = gWord[2];
        holder[2] = gWord[3];
        holder[3] = gWord[0];
        gWord = holder;

        for (int i = 0; i < 4; i++) {
            gWord[i] = sBox(gWord[i]);
        }
        
        gWord[0] = decToHex(Integer.parseInt(gWord[0], 16) ^ Integer.parseInt(roundConst, 16));
        return gWord;
    }

    /**
     * Reverses the values of a given polynomial, used for subBytes
     * @param poly
     * @return 
     */
    public static int[] reverse(int[] poly) {
        int[] newPoly = new int[poly.length];
        for (int i = 0; i < newPoly.length; i++) {
            newPoly[i] = poly[7 - i];
        }
        return newPoly;
    }

    /**
     * Converts a hex value to a binary value
     * @param hex
     * @return 
     */
    public static String hexToBin(String hex) {
        int i = Integer.parseInt(hex, 16);
        String out = Integer.toBinaryString(i);
        if (out.length() != 8) {
            String pad = "";
            for (int j = 0; j < 8 - out.length(); j++) {
                pad += "0";
            }
            out = pad + out;
        }
        return out;
    }

    /**
     * Convert a binary number to its hexadecimal representation
     * @param bin
     * @return 
     */
    public static String binToHex(String bin) {
        bin = bin.trim();
        int i = Integer.parseInt(bin, 2);
        String out = Integer.toHexString(i);
        if (out.length() != 2) {
            out = "0" + out;
        }
        return out;
    }

    /**
     * Converts a decimal to hex representation
     * @param dec
     * @return 
     */
    public static String decToHex(int dec) {
        String out = Integer.toHexString(dec);
        if (out.length() != 2) {
            out = "0" + out;
        }
        return out;
    }

    /**
     * Returns an array representation of a given polynomial
     * @param bin
     * @return 
     */
    public static int[] makePoly(String bin) {
        int[] poly = new int[bin.length()];
        for (int i = 0; i < bin.length(); i++) {
            poly[i] = Integer.parseInt(bin.substring(i, i + 1));
        }

        return poly;
    }

    /**
     * Returns an ArrayList representation of a given polynomial
     * @param bin
     * @return 
     */
    public static ArrayList<Integer> makeAPoly(String bin) {
        ArrayList<Integer> poly = new ArrayList<>();
        for (int i = 0; i < bin.length(); i++) {
            poly.add(Integer.parseInt(bin.substring(i, i + 1)));
        }

        return poly;
    }

    /**
     * Returns a state representation of a given string
     * @param in
     * @return 
     */
    public static String[][] toState(String in) {
        String[][] state = new String[4][4];
        int r = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = in.substring(r, r + 2);
                r += 2;
            }
        }
        return state;
    }

    /**
     * Returns a string representation of an array polynomial
     * @param poly
     * @return 
     */
    public static String toString(int[] poly) {
        String out = "";
        for (int i = 0; i < 8; i++) {
            out += poly[i];
        }
        return out;
    }

    /**
     * Returns a table representation of a given state
     * @param state
     * @return 
     */
    public static String toString(String[][] state) {
        String out = "";
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                out += state[i][j];
                if (j < 3) {
                    out += " ";
                }
            }
            out += "\n";
        }
        return out;
    }
    
    /**
     * Returns a hex stream representation of a given state
     * @param state
     * @return 
     */
    public static String toStream(String[][] state){
        String out = "";
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                out += state[i][j];
            }
        }
        return out;
    }

    /**
     * Schedules 10 sub keys based on a base key.
     * @param key
     * @return 
     */
    public static ArrayList<String[][]> keySchedule(String[][] key) {
        ArrayList<String[][]> keySched = new ArrayList<>();
        String[][] newKey = new String[4][4];
        keySched.add(key);
        String[] gWord;
        String rC = "01";
        String two = "02";
        for(int i = 0; i < 10; i++){
            gWord = g(keySched.get(i)[3], rC);
            newKey[0] = xorWord(keySched.get(i)[0], gWord);
            newKey[1] = xorWord(keySched.get(i)[1], newKey[0]);
            newKey[2] = xorWord(keySched.get(i)[2], newKey[1]);
            newKey[3] = xorWord(keySched.get(i)[3], newKey[2]);
            keySched.add(newKey);
            newKey = new String[4][4];
            rC = binToHex(toString(multiply(makeAPoly(hexToBin(rC)), makeAPoly(hexToBin(two)))));
            rC = binToHex(toString(PLDA(makeAPoly(hexToBin(rC)), mX)[1]));
        }
        return keySched;
    }
    
    /**
     * XORs two columns together and returns the result
     * @param word1
     * @param word2
     * @return 
     */
    public static String[] xorWord(String[] word1, String[] word2){
        String[] result = new String[4];
        for(int i = 0; i < 4; i++){
            result[i] = decToHex(Integer.parseInt(word1[i], 16)^Integer.parseInt(word2[i], 16));
        }
        return result;
    }

    /**
     * EEA implementation used in the GF1 project, needed for PLDA and EEAP
     *
     * @param a
     * @param b
     * @return multiplicative inverse of a as defined by modulus b
     */
    public static int[] EEA(int a, int b) {
        if (b == 0) {
            return new int[]{1, 0};
        } else {
            int q = a / b;
            int r = a % b;
            if (r < 0) {
                r += b;
            }
            int[] R = EEA(b, r);
            int i = (R[0] - q * R[1]) % prime;
            if (i < 0) {
                i += prime;
            }
            return new int[]{R[1], i};
        }
    }

    /**
     * Extended Euclidean Algorithm for Polynomials
     *
     * @param a
     * @param b
     * @return multiplicative inverse of a(x) as defined by irreducible
     * polynomial b(x)
     */
    public static ArrayList[] EEAP(ArrayList<Integer> a, ArrayList<Integer> b) {
        ArrayList<Integer> u = new ArrayList<>();
        ArrayList<Integer> v = new ArrayList<>();
        for (int i = 0; i < a.size(); i++) {
            a.set(i, mod(a.get(i)));
        }
        for (int i = 0; i < b.size(); i++) {
            b.set(i, mod(b.get(i)));
        }
        if (b.isEmpty() || b.get(0) == 0) {
            u.add(1 * EEA(a.get(0), prime)[0]);
            v.add(0);
            return new ArrayList[]{u, v};
        } else {
            ArrayList[] Q = PLDA(a, b);
            ArrayList<Integer> qX = Q[0];
            ArrayList<Integer> rX = Q[1];
            ArrayList[] R = EEAP(b, rX);
            return new ArrayList[]{R[1], subtract(R[0], multiply(qX, R[1]))};
        }
    }

    /**
     * Polynomial Long Division Algorithm
     *
     * @param n
     * @param d
     * @return quotient q(x) and remainder r(x)
     */
    public static ArrayList[] PLDA(ArrayList<Integer> n, ArrayList<Integer> d) {
        int size = n.size() - d.size();
        for (int i = 0; i < n.size(); i++) {
            n.set(i, mod(n.get(i)));
        }
        for (int i = 0; i < d.size(); i++) {
            d.set(i, mod(d.get(i)));
        }
        ArrayList<Integer> rX = n;
        ArrayList<Integer> qX = new ArrayList<>();
        ArrayList<Integer> op = new ArrayList<>();
        for (int i = 0; i <= size; i++) {
            qX.add(0);
        }
        int t;
        while ((rX.get(0) != 0) && (rX.size() - 1) >= (d.size() - 1)) {
            t = mod(rX.get(0) * EEA(d.get(0), prime)[0]);
            //qX.add(t);
            op.add(t);
            for (int i = 1; i <= rX.size() - d.size(); i++) {
                op.add(0);
            }
            rX = subtract(rX, multiply(d, op));
            trimZeroes(rX);
            qX = add(qX, op);
            op = new ArrayList<>();
        }
        if (qX.isEmpty()) {
            qX.add(0);
        }
        return new ArrayList[]{qX, rX};
    }

    /**
     * Adds two ArrayList representations of polynomials
     *
     * @param a
     * @param b
     * @return result
     */
    public static ArrayList<Integer> add(ArrayList<Integer> a, ArrayList<Integer> b) {
        ArrayList<Integer> res = new ArrayList<>();
        int diff;
        if (a.size() == b.size()) {
            for (int i = 0; i < a.size(); i++) {
                res.add(mod(a.get(i) + b.get(i)));
            }
            trimZeroes(res);
            return res;
        } else if (a.size() > b.size()) {
            diff = a.size() - b.size();
            for (int i = 0; i < a.size(); i++) {
                if (i < diff) {
                    res.add(mod(a.get(i)));
                } else {
                    res.add(mod(a.get(i) + b.get(i - diff)));
                }
            }
            trimZeroes(res);
            return res;
        } else {
            diff = b.size() - a.size();
            for (int i = 0; i < b.size(); i++) {
                if (i < diff) {
                    res.add(mod(b.get(i)));
                } else {
                    res.add(mod(a.get(i - diff) + b.get(i)));
                }
            }
            trimZeroes(res);
            return res;
        }
    }

    /**
     * Subtracts two ArrayList representations of polynomials
     *
     * @param a
     * @param b
     * @return result
     */
    public static ArrayList<Integer> subtract(ArrayList<Integer> a, ArrayList<Integer> b) {
        boolean lead = true;
        int diff;
        ArrayList<Integer> res = new ArrayList<>();
        if (a.size() == b.size()) {
            for (int i = 0; i < a.size(); i++) {
                res.add(mod(a.get(i) - b.get(i)));
            }
            trimZeroes(res);
            return res;
        } else if (a.size() > b.size()) {
            diff = a.size() - b.size();
            for (int i = 0; i < a.size(); i++) {
                if (i < diff) {
                    res.add(mod(a.get(i)));
                } else {
                    res.add(mod(a.get(i) - b.get(i - diff)));
                }
            }
            trimZeroes(res);
            return res;
        } else {
            diff = b.size() - a.size();
            for (int i = 0; i < b.size(); i++) {
                if (i < diff) {
                    res.add(mod(0 - b.get(i)));
                } else {
                    res.add(mod(a.get(i - diff) - b.get(i)));
                }
            }
            trimZeroes(res);
            return res;
        }
    }

    /**
     * Multiplies two ArrayList representations of polynomials
     *
     * @param a
     * @param b
     * @return result
     */
    public static ArrayList<Integer> multiply(ArrayList<Integer> a, ArrayList<Integer> b) {
        int newPower = (a.size() - 1) + (b.size() - 1);
        ArrayList<Integer> res = new ArrayList<>();
        for (int i = 0; i <= newPower; i++) {
            res.add(i, 0);
        }

        for (int i = 0; i < a.size(); i++) {
            for (int j = 0; j < b.size(); j++) {
                res.set((i + j), (a.get(i) * b.get(j)) + res.get(i + j));
            }
        }

        for (int i = 0; i < res.size(); i++) {
            res.set(i, mod(res.get(i)));
        }
        trimZeroes(res);
        return res;
    }

    /**
     * Multiplies a single factor with attached power into an ArrayList
     * representation of a polynomial
     *
     * @param a
     * @param factor
     * @param size
     * @return result
     */
    public static ArrayList<Integer> multiply(ArrayList<Integer> a, int factor, int size) {
        ArrayList<Integer> result = new ArrayList<>(a);
        while (result.size() < size) {
            result.add(0);
        }

        for (int i = 0; i < a.size(); i++) {
            result.set(i, mod(a.get(i) * factor));
        }

        return result;
    }

    /**
     * Returns the result of a mod b
     *
     * @param i
     * @return i
     */
    public static int mod(int i) {
        i %= prime;
        if (i < 0) {
            return i + prime;
        }
        return i;
    }

    /**
     * Trims leading zeroes from polynomials
     *
     * @param r
     * @return r
     */
    public static int trimZeroes(ArrayList<Integer> r) {
        if (r.size() <= 0) {
            return 0;
        }
        int i = 0;
        while (r.get(i) == 0) {
            if (r.size() == 1) {
                break;
            }
            r.remove(i);
        }
        return i;
    }

    /**
     * Pads the end of a polynomial to add remaining factors of x
     *
     * @param a
     * @param size
     * @return a
     */
    public static ArrayList<Integer> padTail(ArrayList<Integer> a, int size) {
        while (a.size() <= size) {
            a.add(0);
        }
        return a;
    }

    /**
     * Prints the coefficients of a polynomial to a line
     *
     * @param a
     * @return
     */
    public static String toString(ArrayList<Integer> a) {
        String out = "";
        for (int i = 0; i < a.size(); i++) {
            out += a.get(i);
        }
        return out;
    }
}