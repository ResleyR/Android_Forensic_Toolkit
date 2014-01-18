/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package android.forensic.toolkit;

/**
 *
 * @author Resley Rodrigues
 */
public class MFT {
    
 //   int flag;       //at byte 21
  //  int Length of File Name; //1 byte
    
    String File_Identifier = "";     //4 bytes          0       0x00-0x03
    int Offset_to_update_sequence;//2 bytes             4       0x04 0x05
    int Size_of_update_sequence;    //2 bytes           6       0x06 0x07
    int $LogFile_Sequence_Number;   //8 bytes           8       0x08-0x0F
    int Sequence_Number;            //2 bytes           16      0x10 0x11
    int Reference_Count;            //2 bytes           18      0x12 0x13
    int Offset_to_Update_Sequence_Array;//2 bytes       20      0x14 0x15
    int Flags;                      //2 bytes           22      0x16 0x17
    int Real_size_of_the_FILE_record;//4 bytes          24      0x18-0x1B       //logical size
    int allocated_size_of_the_FILE_record;//4 bytes     28      0x1C-0x1F       //physical size
    int File_reference_to_the_base_FILE_record; //8 bytes32     0x20-0x27       //0 means itself
    int Next_Attribute_Id;          //4 bytes           40      0x28-0x2B
    int Id_of_this_FILE;            //4 bytes           44      0x2C-0x2F  
        
    //If Flags field has bit 1 set, it means that file is in-use. Zero means it is deleted.
    
    //Starting from 0x48, we have Standard Information Attribute (second bold section):
    int File_Creation_Time;         //8 bytes           72
    int File_Last_Modification_Time;//8 bytes           80
    int File_Last_Modification_Time_for_File_Record;//8 bytes   88
    int File_Access_Time_for_File_Record;//8 bytes      96

    
    //Following standard attribute header,
    //we have File Name Attribute belonging to DOS name space,
    //short file names, (offset 0xA8)
    //and again following standard attribute header,
    //we have File Name Attribute belonging to Win32 name space,
    //long file names, (offset 0x120):
    
    int File_Reference_to_the_Parent_Directory; //8 bytes       288
    int File_Modification_Times;                //32 bytes      296
    long Allocated_Size_of_the_File;            //8 bytes       328
    long Real_Size_of_the_File;                 //8 bytes       336
    int FlagsL;                                 //8 bytes       344
    int Length_of_File_Name;                    //1 byte        352     0xF0
    int File_Name_Space;                        //1 byte        353     0xF1
    String File_Name = "";                      //Length_of_File_Name * 2 bytes 354     0xF2-...
    
    //we can extract file name, File Creation and
    //Modification times, and Parent Directory Record number.
    
    //Starting from offset 0x188, there is a non-resident Data attribute.
    
    int Attribute_Type;                 //4 bytes (e.g. 0x80)
    int Length_including_header;        //4 bytes
    int Non_resident_flag;              //1 byte
    int Name_length;                    //1 byte
    int Offset_to_the_Name;             //2 bytes
    int FlagsNR;                          //2 bytes
    int Attribute_Id;                   //2 bytes
    int Starting_VCN;                   //8 bytes
    int Last_VCN;                       //8 bytes
    int Offset_to_the_Data_Runs;        //2 bytes
    int Compression_Unit_Size;          //2 bytes
    int Padding;                        //4 bytes
    int Allocated_size_of_the_attribute;//8 bytes
    int Real_size_of_the_attribute;     //8 bytes
    int Initialized_data_size_of_the_stream;    //8 bytes

    //Data_Runs_...
    private static final String Image = "/res/deleted_file.png";

    public boolean set_data(byte[] ar, long startSector){
        int i;
        int j;//=242;
        FileRecord fileRec = new FileRecord();
                String size = "NTFS Sizer Error";
                String attrib="";
        Offset_to_Update_Sequence_Array = Utils.hexToInt(Utils.hex(ar[20]), Utils.hex(ar[21]));
        for(i=0;i<4;i++)        //byte 0-3  0x00-0x03
            File_Identifier = File_Identifier.concat(String.valueOf(Utils.hexToText(Utils.hex(ar[i]))));
        //Flags byte 22-23 0x16-0x17
        Flags = Utils.hexToInt(Utils.hex(ar[22]), Utils.hex(ar[23]));
        if(Flags!=0){
            return false;
        }
        do {
            System.out.println("Offset: "+Utils.hex(Offset_to_Update_Sequence_Array));
        
            i = Offset_to_Update_Sequence_Array;
            System.out.print("i: "+Utils.hex(i));
            Attribute_Type = Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i++]),Utils.hex(ar[i++]), Utils.hex(ar[i++]));
            if(Attribute_Type==-1){
                return false;
            }
            System.out.print("\tType: "+Utils.hex(Attribute_Type));
            System.out.print("\ti: "+Utils.hex(i));
            int temp = Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i++]),Utils.hex(ar[i++]), Utils.hex(ar[i++]));      //Offset + Length of Attribute
            System.out.print("\tLength: "+temp+"\t\t");
            Offset_to_Update_Sequence_Array += temp;
        }while(Attribute_Type!=48);     //Loop until Attribute Type is 0x30 (Std Info)
        System.out.println("");
      //  i=224;
     //   Real_Size_of_the_File = Utils.hexToInt(Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++]), Utils.hex(ar[i++]));
        i+=80;
        Name_length = Utils.hexToInt(Utils.hex(ar[i]),"0");
        System.out.println("Offset: "+Utils.hex(i)+"\tName length: "+Utils.hex(ar[i++]));
        i++;
        for(j=0;j<(Name_length*2);j++){
           File_Name = File_Name.concat(String.valueOf(Utils.hexToText(Utils.hex(ar[i+j]))));
        }
        System.out.println(File_Name);
        fileRec.setName(File_Name);
                        fileRec.setAttributes(attrib);
                        fileRec.setStartSector(startSector);
                        fileRec.setImage(Image);
                        fileRec.setFileSize(size);
                        fileRec.setFoundAt(j);
                        NTFS.files.add(fileRec);
        return true;
    }
    
    public void print_data(javax.swing.JTextArea a){
        a.append(File_Identifier + "\t\t" + Flags + "\t\t" + Name_length + "\t\t" + File_Name +"\t\t"+
               // Utils.getSize(Real_Size_of_the_File)+
                "\n");
    }
    
   
}
