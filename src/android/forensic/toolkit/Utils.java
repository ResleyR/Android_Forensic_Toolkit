/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package android.forensic.toolkit;

import java.text.DecimalFormat;

/**
 *
 * @author Resley Rodrigues
 */
public class Utils {
//static String[] hexArray = {
//"00","01","02","03","04","05","06","07","08","09","0A","0B","0C","0D","0E","0F",
//"10","11","12","13","14","15","16","17","18","19","1A","1B","1C","1D","1E","1F",
//"20","21","22","23","24","25","26","27","28","29","2A","2B","2C","2D","2E","2F",
//"30","31","32","33","34","35","36","37","38","39","3A","3B","3C","3D","3E","3F",
//"40","41","42","43","44","45","46","47","48","49","4A","4B","4C","4D","4E","4F",
//"50","51","52","53","54","55","56","57","58","59","5A","5B","5C","5D","5E","5F",
//"60","61","62","63","64","65","66","67","68","69","6A","6B","6C","6D","6E","6F",
//"70","71","72","73","74","75","76","77","78","79","7A","7B","7C","7D","7E","7F",
//"80","81","82","83","84","85","86","87","88","89","8A","8B","8C","8D","8E","8F",
//"90","91","92","93","94","95","96","97","98","99","9A","9B","9C","9D","9E","9F",
//"A0","A1","A2","A3","A4","A5","A6","A7","A8","A9","AA","AB","AC","AD","AE","AF",
//"B0","B1","B2","B3","B4","B5","B6","B7","B8","B9","BA","BB","BC","BD","BE","BF",
//"C0","C1","C2","C3","C4","C5","C6","C7","C8","C9","CA","CB","CC","CD","CE","CF",
//"D0","D1","D2","D3","D4","D5","D6","D7","D8","D9","DA","DB","DC","DD","DE","DF",
//"E0","E1","E2","E3","E4","E5","E6","E7","E8","E9","EA","EB","EC","ED","EE","EF",
//"F0","F1","F2","F3","F4","F5","F6","F7","F8","F9","FA","FB","FC","FD","FE","FF"};
    private Utils() {
    }

    public static String byteToHex(byte[] a) {
        StringBuilder sb = new StringBuilder();
        for (byte b : a) {
            sb.append(String.format("%02X", b & 0xff));
        }
        return sb.toString();
    }

    public static long hexToInt(String a, String b, String c, String d, String e, String f, String g, String h) {
        g = h.concat(g);
        f = g.concat(f);
        e = f.concat(e);
        d = e.concat(d);
        c = d.concat(c);
        b = c.concat(b);
        a = b.concat(a);
        try{
        return  Long.parseLong(a, 16);
        }catch(NumberFormatException nfe){
            return -1;
        }
    }

    public static int hexToInt(String a, String b, String c, String d) {
        c = d.concat(c);
        b = c.concat(b);
        a = b.concat(a);
        try{
        return  Integer.parseInt(a, 16);
        }catch(NumberFormatException nfe){
            return -1;
        }
    }

    public static int hexToInt(String a, String b) {
        a = b.concat(a);
        return Integer.parseInt(a, 16);
    }

    public static char hexToText(String a) {
        int b = hexToInt(a, "00");
        char c = (char) Integer.parseInt(Integer.toString(b), 10);
        return c;

    }

    public static String getSize(long sizeLong) {
        double size = (double) sizeLong;
        DecimalFormat dFormat = new DecimalFormat("#.##");
        String strSize = "0 bytes";
        if (size > 1024) {
            size /= 1024;
            strSize = dFormat.format(size) + " KB";
            if (size > 1024) {
                size /= 1024;
                strSize = dFormat.format(size) + " MB";
                if (size > 1024) {
                    size /= 1024;
                    strSize = dFormat.format(size) + " GB";
                }
            }
        }
        return strSize;
    }

    public static String hex(int n) {
        return String.format("0x%8s", Integer.toHexString(n).toUpperCase()).replace(' ', '0').substring(8);
    }
}
