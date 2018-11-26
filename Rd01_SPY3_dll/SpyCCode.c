/* ***************************************************************************
|
| Project Name: DESAY SV 77G MF RADAR PLATFORM
|    File Name: SpyCCode.c
|
|  Description: Spy C Code Implementation for RD02 can upgrade
|
|               Target systems: S32R274
|
|               Compiler:       GNU tools
|
|************************************************************************** */

/* ***************************************************************************
|               C O P Y R I G H T
|-----------------------------------------------------------------------------
| Copyright (c) 2013-2018 by Huizhou Desay SV Automotive Co., Ltd.  All rights reserved.
|-----------------------------------------------------------------------------
|               R E V I S I O N   H I S T O R Y
|-----------------------------------------------------------------------------
| Date       Ver  Author            Description
| ---------  ---  ------  ----------------------------------------------------
| 2018-06-12  0.1  Chen Dingding    - init version
| 2018-06-18  0.2  Chen Dingding    - release first version
| 2018-06-23  0.3  Chen Dingding    - optimize upgrade process
| 2018-06-24  0.4  Chen Dingding    - shorten transfer data period
| 2018-06-25  0.5  Chen Dingding    - re-define DataStr avoid data convert error
| 2018-06-27  0.6  Chen Dingding    - defined CurrentBlockIndex as U32 adapt for App file length
|                                   - add wait receive response after mcu restart.
| 2018-08-30  0.7  Chen Dingding    - fix file choose bug.
|
|************************************************************************** */
#include "vspy.h"
#include <io.h>
#include <direct.h>


//#define __SUPPORT_DSP_SLAVE_DOWNLOAD__

#define cyclictimer 0

// module variables
typedef unsigned char   U8;
typedef unsigned int U32;
typedef unsigned short U16;

char sourcefiles[100][200];
char sourceFileMove[100][200];
unsigned int fileNumber;
unsigned int curfileNumber;
char sourceFile[200];
char sourceFileFolder[200];
char sourceFileScan[200];
char logFile[200];
U8 DocumentName[200];
U32 DocumentNameLength;

U8  upgrade_finish = 0;

int updateflag = 0;

unsigned char DataStr[65535][192];// program file data buffer memory

U8 gRxDataBuffer[8];
double gTxDataBuffer[2048];
unsigned char SecuritySeed[4];
unsigned char SecurityKey[4];
unsigned long txCount = 0;
U8 HexDataArray[1000];


U32 DataBlockLength;

#define MaxDataLengh  192

int DataCurrPos = 0;
int DataCurrIndex = 0;
U32 DataCurrAddr = 0;
U32 DataTotalLen = 0;
U32 DataBlockAddr = 0;
int DataBlockIndex = 0;
U32 DataPageAddr;

U8 crc = 0x00; /* initial value */
U8 tmp = 0x00;

U16 file_checksum;
U32 crc_table[256];

U32 TransferBlockSize;
U32 LastTransferBlockSize;

int Repart_flag = 0;
int First_data_Filename = 0;

U32 CurrentTotalLen = 0;
U32 CurrentBlockIndex;
U32 CurrentBlockCnt;
int CurrBlock;
int CurrPos;

int minSendInterval;
int wait30Freq;

int downloadType;

char softversion[30];//="RD02MF_18.07.01_B2";
U8 softwareVersionoffset = 0;
U8 softwareVersionRespCnt = 0;


#if defined(__SUPPORT_DSP_SLAVE_DOWNLOAD__)
int DSPDLType;

enum DSPDownLoadType
{
	DSP_UNKNOWN_DOWNLOAD,
	DSP_MASTER_DOWNLOAD,
	DSP_SLAVE_DOWNLOAD,
};
#endif

enum DownloadType
{
	DOWNLOAD_NONE,
	MCU_DOWNLOAD,
	DSP_DOWNLOAD,
};

enum DiagStatusType
{
	DiagNone = 0,
	StartExtendedSession = 1,
	DisableDTCstorage,
	DisableNMAndCommunicationMessage,
	RequestResetMcuPre,
	StartReProgramSection,
	RequestSecuritySeed,
	SendSecurityKey,
	StartEraseMemoryProcedure,
	RequestEraseMemoryProcedureResult,
	StopEraseMemoryProcedure,
	RequestDownload,
	TransferDataBlock,
	StopTransferData,
	StartCheckProgramDependency,
	RequestCheckProgramDependencyResult,
	StopCheckProgramDependency,
	StartCheckApplicationProgramValidation,
	RequestCheckApplicationProgramValidationResult,
	StopCheckApplicationProgramValidation,
	RequestResetMcu,
	ChangeToProgrammingSession,
	ChangeToExtendedSession,
	EnableNMAndCommunicationMessage,
	EnableDTCstorage,
	ClearAllDTC,
	ChangeToDefaultSession,
	RequestStopResetMcu,
	StartMCUDownload,
	StartWriteFlagMCUDownload,
	SetMCUDate,
	GetSoftwareVersion,
	Inquire_System_State,
};
enum DiagStatusType Diag_Status;

U16 crctab[256] =
{
	0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
	0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
	0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
	0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
	0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
	0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
	0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
	0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
	0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
	0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
	0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
	0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
	0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
	0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
	0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
	0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
	0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
	0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
	0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
	0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
	0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
	0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
	0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
	0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
	0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
	0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
	0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
	0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
	0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
	0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
	0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
	0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
};


TX_Diag_Func_Rx_HS_CAN Diag_Func_Request;
TX_AVM_Phys_Diag_Rx_Req_to_DVD_HS_CAN Diag_Phys_Request;

void GetSoftwareVersion_Rep(void);
void SendFC(void);
void logflashstatues(unsigned int n);
void DiagSend3E(void);
void DiagStopResetMcu(void);
void DiagStopResetMcuResp(void);
void DiagStartMCUDownload(void);
void DiagStartMCUDownloadResp(void);
void DiagStartWriteFlagMCUDownload(void);
void DiagStartWriteFlagMCUDownloadResp(void);
void Inquire_System_State_Req(void);
void DiagStartExtendedSession(void);
void DiagStartExtendedSessionResp(void);
void DiagDisableDTCstorage(void);
void DiagDisableDTCstorageResp(void);
void DiagDisableNMAndCommunicationMessage(void);
void DiagDisableNMAndCommunicationMessageResp(void);
void DiagResetMcuPre(void);
void DiagResetMcuPreResp(void);
void DiagStartReprogramSection(void);
void DiagStartReprogramSectionResp(void);
void DiagRequestSecuritySeed(void);
void DiagRequestSecuritySeedResp(void);
void DiagSendSecurityKey(void);
void DiagSendSecurityKey_MCU(void);
void DiagSendSecurityKeyResp(void);
void SetMCUDateResp(void);
void DiagEraseFlashSector_StartRoutine(void);
void DiagEraseFlashSector_StartRoutineResps(void);
void DiagEraseFlashSector_RequestRoutineResult(void);
void DiagEraseFlashSector_RequestRoutineResultResps(void);
void DiagEraseFlashSector_StopRoutine(void);
void DiagEraseFlashSector_StopRoutineResps(void);
void DiagRequestDownloadData(void);
void DiagRequestDownloadDataResp(void);
void DiagTransferData(void);
void DiagTransferDataResp(void);
void DiagStopTransferData(void);
void DiagStopTransferDataResp(void);
void DiagCheckProgramDependency_StartRoutine(void);
void DiagCheckProgramDependency_StartRoutineResp(void);
void DiagCheckProgramDependency_RequestRoutineResult(void);
void DiagCheckProgramDependency_RequestRoutineResultResp(void);
void DiagCheckProgramDependency_StopRoutine(void);
void DiagCheckProgramDependency_StopRoutineResp(void);
void DiagCheckApplicationProgramValidation_StartRoutine(void);
void DiagCheckApplicationProgramValidation_StartRoutinResp(void);
void DiagCheckApplicationProgramValidation_RequestRoutineResult(void);
void DiagCheckApplicationProgramValidation_RequestRoutineResultResp(void);
void DiagCheckApplicationProgramValidation_StopRoutine(void);
void DiagCheckApplicationProgramValidation_StopRoutineResp(void);
void DiagResetMcu(void);
void DiagResetMcuResp(void);
void DiagChangeToExtendedSession(void);
void DiagChangeToExtendedSessionResp(void);
void DiagEnableNMAndCommunicationMessage(void);
void DiagEnableNMAndCommunicationMessageResp(void);
void DiagEnableDTCstorage(void);
void DiagEnableDTCstorageResp(void);
void DiagClearAllDTC(void);
void DiagClearAllDTCResp(void);
void DiagChangeToDefaultSession(void);
void DiagChangeToDefaultSessionResp(void);
void DiagChangeToProgrammingSession(void);
void DiagChangeToProgrammingSessionResp(void);

void ReadFileData(void);
void ReadHexFileData(char Data[]);
void ReadS19FileData(char Data[]);
U8 AsciiToHex(char ch1, char ch2);
U8 Ascii2Hex(char cha);
void CalcCRC(U8 data[], int length);
void Pad0xff(void);
void CopyStringToBuffer(char Str[], char Buf[], int Offset, int Len);
void ConvertAsciiStringToHexArray(char Data[], int length);
U8 S19checkOneLineChecksum(U8 Data[], int length);
U8 HexCheckOneLineCheckSum(U8 Data[], int length);
void AddDataToDataBuffer(U32 Addr, U8 Data[], int Len);
void CalcChecksum(U8 data[], int length);
U32 CalculateSectorDataCrc16(void);
U32 crc16(U32 Incrc, U8 buffer[], U32 size);

void calcKey(unsigned char seed[]);
void calcKey_MCU(unsigned char seed[]);

void FunDiagRequest(void);
void DiagMessageResp(void);

void SendDataAtFunctionalConnector(double sendData[], unsigned short sendsize);
void SendDataAtFhysicalConnector(double sendData[], unsigned short sendsize);
void SendDataAtFhysicalConnector_SecondPart(double sendData[], unsigned short sendsize);


/* compose from byte stream a 32 bit data */
#define DescMake32Bit(hiHiByte,hiLoByte,loHiByte,loLoByte)           ((U32)((((U32)(hiHiByte))<<24)| \
                                                                     (((U32)(hiLoByte))<<16)| \
                                                                     (((U32)(loHiByte))<<8) | \
                                                                     ((U32)(loLoByte))))

/*************************************************************************************************************************/
/*****************************************************************************************
*  Name        : ReadFileData
*  Description :
*  Parameter   : unsigned int number
*  Returns     :
*****************************************************************************************/
void ReadFileData(unsigned int number)
{
	FILE *fp;
	char temstr[500];

	fopen_s(&fp, sourcefiles[number], "r");//get file point number is 1,so begin at second line

	if (NULL == fp)
	{
		printf("Read file error!\n");
	}
	else
	{
		while (fgets(temstr, 500, fp) != NULL)//distinguish file types note this while
		{
			if (temstr[0] == 'S')
			{
				ReadS19FileData(temstr);
			}
			else if (temstr[0] == ':')
			{
				ReadHexFileData(temstr);
			}
		}

		fclose(fp);

		if (downloadType == MCU_DOWNLOAD)/*pad 0xff*/
		{
			Pad0xff();
		}

		printf("Read file finish, you can start download!\n");
	}
}
/*****************************************************************************************
*  Name        : ReadHexFileData
*  Description :
*  Parameter   : char Data[]
*  Returns     :
*****************************************************************************************/
void ReadHexFileData(char Data[])
{
	int i, loopCnt;
	char tempBuffer[600];
	U32 TempAddress;
	U8 temhexstr[300];
	loopCnt = AsciiToHex(Data[1], Data[2]);
	loopCnt = (int)(loopCnt << 1) + 10;
	CopyStringToBuffer(Data, tempBuffer, 1, loopCnt);
	ConvertAsciiStringToHexArray(tempBuffer, loopCnt);
	loopCnt = loopCnt >> 1;
	//write("the string is %s, the cnt is %d",tempBuffer,loopCnt);
	if (HexCheckOneLineCheckSum(HexDataArray, loopCnt) == 1)
	{
		if (HexDataArray[3] == 0x00)// data seg
		{
			TempAddress = (U32)HexDataArray[1];
			TempAddress = (U32)(TempAddress << 8) + (U32)HexDataArray[2];
			TempAddress = TempAddress + DataPageAddr;

			for (i = 0; i < loopCnt - 5; i++)
			{
				temhexstr[i] = HexDataArray[i + 4];
			}
			//write("the address is %X",TempAddress);
			AddDataToDataBuffer(TempAddress, temhexstr, loopCnt - 5);
		}
		else if (HexDataArray[3] == 0x01)// end file seg
		{
			//write("there are total %d segment of data are read !!!",read_seg);
			//putValue (ProgramSectionChecksum,file_checksum);

			//putValue(PromgramIndicationStr, "Procedure File Read Finish!!!");
			//sysSetVariableInt(sysvar::ReadFile::sysCodeFileLength, DataTotalLen);

			//file_checksum = (U32)(StrChecksum[3]<<24)+(U32)(StrChecksum[2]<<16)+(U32)(StrChecksum[1]<<8)+(U32)(StrChecksum[0]);
			//write("the file checksum is: 0x%x !",file_checksum);

		}
		else if (HexDataArray[3] == 0x02)// Extended Linear Address as 20 bit
		{
			DataPageAddr = (U32)HexDataArray[4];
			DataPageAddr = (U32)(DataPageAddr << 8) + (U32)HexDataArray[5];
			DataPageAddr = (U32)(DataPageAddr << 4);
		}
		else if (HexDataArray[3] == 0x04)// Extended Linear Address as 32 bit
		{
			DataPageAddr = (U32)HexDataArray[4];
			DataPageAddr = (U32)(DataPageAddr << 8) + (U32)HexDataArray[5];
			DataPageAddr = (U32)(DataPageAddr << 16);
		}
	}
}

/*****************************************************************************************
*  Name        : ReadS19FileData
*  Description :
*  Parameter   : char Data[]
*  Returns     :
*****************************************************************************************/
void ReadS19FileData(char Data[])
{
	int i;
	int loopCnt;
	int datalength;
	char tempBuffer[1000];
	U32 TempAddress;
	U8 temhexstr[1000];


	loopCnt = AsciiToHex(Data[2], Data[3]);//Data[2] is 8. Data[3] is 5. 85. loopCnt is 133(dec)
	//printf("=====Data === %s\n", Data);
	//printf("=====loopCnt === %x\n", loopCnt);
	loopCnt = (int)(loopCnt << 1) + 2;//loopCnt is 0x10C (268dec)
	CopyStringToBuffer(Data, tempBuffer, 2, loopCnt);//delete S3 flow this step
	//printf("=====tempBuffer === %s\n", tempBuffer);

	ConvertAsciiStringToHexArray(tempBuffer, loopCnt);//just copy data from vtempBuffer to HexDataArray
	//printf("=====tempBuffer === %s\n", tempBuffer);

	loopCnt = loopCnt >> 1;//recover loopCnt 134dec

	if (S19checkOneLineChecksum(HexDataArray, loopCnt) == 1)//Check line by line 
	{
		if (Data[1] == '0') // S0 seg so represent file info
		{
			//printf("in s0\n");
			TempAddress = (U32)HexDataArray[1];
			TempAddress = (U32)(TempAddress << 8) + (U32)HexDataArray[2];//0002
			DocumentName[0] = loopCnt;//real address info is 4 bytes:0002D24C,//loopCnt is 22, if+s0 = 23

			for (i = 0; i < loopCnt - 4; i++)
			{
				DocumentName[i + 1] = HexDataArray[i + 3];
			}

			DocumentNameLength = loopCnt + 1;
			//printf("=====DocumentNameLength === %x\n", DocumentNameLength);//DocumentNameLength is 23dec
		}
		else if (Data[1] == '2')// S2 seg
		{
			//printf("in s2\n");
			TempAddress = (U32)HexDataArray[1];
			TempAddress = (U32)(TempAddress << 8) + (U32)HexDataArray[2];
			TempAddress = (U32)(TempAddress << 8) + (U32)HexDataArray[3];
			for (i = 0; i < loopCnt - 5; i++)
			{
				temhexstr[i] = HexDataArray[i + 4];
			}
			AddDataToDataBuffer(TempAddress, temhexstr, loopCnt - 5);
			//printf("=====DataTotalLen === %x\n", DataTotalLen);
		}
		else if (Data[1] == '3') // S3 seg
		{
			TempAddress = (U32)HexDataArray[1];//get address
			TempAddress = (U32)(TempAddress << 8) + (U32)HexDataArray[2];
			TempAddress = (U32)(TempAddress << 8) + (U32)HexDataArray[3];
			TempAddress = (U32)(TempAddress << 8) + (U32)HexDataArray[4];

			for (i = 0; i < loopCnt - 6; i++)
			{
				temhexstr[i] = HexDataArray[i + 5];//get data
			}

			AddDataToDataBuffer(TempAddress, temhexstr, loopCnt - 6);//copy data to global DataArray, DataTotalLen will be got
		}
		else if (Data[1] == '7')
		{
			//printf("in s7\n");//check filename and data
			//printf("DataTotalLen is %d\n",DataTotalLen);/*DataTotalLen is file to be burn length*/
			DocumentName[DocumentNameLength - 4] = (DataTotalLen & 0xFF000000) >> 24;//get real address info-> 0002D24C and delete cs add this 4 bytes
			DocumentName[DocumentNameLength - 3] = (DataTotalLen & 0x00FF0000) >> 16;
			DocumentName[DocumentNameLength - 2] = (DataTotalLen & 0x0000FF00) >> 8;;
			DocumentName[DocumentNameLength - 1] = (DataTotalLen & 0x000000FF);

			CalcChecksum(DocumentName, DocumentNameLength);

			for (i = 0; i < (DataTotalLen / MaxDataLengh); i++)
			{
				CalcChecksum(DataStr[i], MaxDataLengh);
			}

			datalength = DataTotalLen % MaxDataLengh;

			CalcChecksum(DataStr[i], datalength);

			crc = ~((U8)tmp);

			printf("=====crc === %x\n", crc);
		}
	}
}

/*****************************************************************************************
*  Name        : AddDataToDataBuffer
*  Description :
*  Parameter   : U32 Addr, U8 Data[], int Len
*  Returns     :
*****************************************************************************************/
void AddDataToDataBuffer(U32 Addr, U8 Data[], int Len)
{
	int i = 0;

	if (DataTotalLen == 0)
	{
		DataCurrPos = 0;
		DataBlockAddr = Addr;/*get start address*/
	}

	//printf("DataBlockAddr is %x\n",DataBlockAddr);

	for (i = 0; i < Len; i++)
	{
		DataStr[DataCurrIndex][DataCurrPos] = Data[i];
#if 0
		if (kk == 0)
		{
			if (i < 50)
			{
				printf("Data[%d]=%x,DataStr[%d][%d]=%x,%d\n", i, Data[i], DataCurrIndex, DataCurrPos, DataStr[DataCurrIndex][DataCurrPos], sizeof(DataStr[DataCurrIndex][DataCurrPos]));
			}
			else
			{
				kk = 1;
			}
		}
#endif

		if (++DataCurrPos >= MaxDataLengh)
		{
			DataCurrIndex++;
			DataCurrPos = 0;
		}
	}

	DataTotalLen += Len;
}

/*****************************************************************************************
*  Name        : Pad0xff
*  Description : read file ok and pad 0xff
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void Pad0xff(void)
{
	int i = 0;
	int padCount = 512 - (DataTotalLen % 512);

	printf(" DataCurrIndex DataCurrPos is %d, %d\n", DataCurrIndex, DataCurrPos);
	printf(" DataTotalLen is %d\n", DataTotalLen);
	for (i = 0; i < padCount; i++)
	{
		DataStr[DataCurrIndex][DataCurrPos] = 0xFF;
		if (++DataCurrPos >= MaxDataLengh)
		{
			DataCurrIndex++;
			DataCurrPos = 0;
		}
	}

	printf(" DataCurrIndex DataCurrPos is %d, %d\n", DataCurrIndex, DataCurrPos);
	DataTotalLen += padCount;
	printf(" DataTotalLen is %d\n", DataTotalLen);
}
/*****************************************************************************************
*  Name        : init_crc_table
*  Description :
*  Parameter   :
*  Returns     :
*****************************************************************************************/
void init_crc_table(void)
{
	U32 c;
	U32 i, j;

	for (i = 0; i < 256; i++)
	{
		c = (U32)i;
		for (j = 0; j < 8; j++)
		{
			if (c & 1)
				//{c = 0x04C11DB7 ^(c >> 1);}
			{
				c = 0xedb88320 ^ (c >> 1);
			}
			else
			{
				c = c >> 1;
			}
		}
		crc_table[i] = c;
	}
}
/*****************************************************************************************
*  Name        : crc32
*  Description :
*  Parameter   : U32 Incrc, U8 buffer[], U32 size
*  Returns     :
*****************************************************************************************/
U32 crc32(U32 Incrc, U8 buffer[], U32 size)
{
	U32 i;
	U32 crc;

	crc = Incrc;

	for (i = 0; i < size; i++)
	{
		crc = crc_table[(crc ^ buffer[i]) & 0xff] ^ (crc >> 8);
	}
	return ~crc;
}
/*****************************************************************************************
*  Name        : Calculate_Crc32
*  Description :
*  Parameter   : U8 buffer[], U32 size
*  Returns     :
*****************************************************************************************/
U32 Calculate_Crc32(U8 buffer[], U32 size)
{
	U32 crc;
	init_crc_table();
	crc = crc32(0xFFFFFFFF, buffer, size);
	return crc;
}
/*****************************************************************************************
*  Name        : hex2bcd
*  Description :
*  Parameter   : U8 input
*  Returns     :
*****************************************************************************************/
U8 hex2bcd(U8 input)
{
	return ((input / 10) << 4) + (input % 10);
}
/*****************************************************************************************
*  Name        : AsciiToHex
*  Description :
*  Parameter   : char ch1, char ch2
*  Returns     :
*****************************************************************************************/
U8 AsciiToHex(char ch1, char ch2)
{
	U8 i, j;
	U8 hexval;
	i = Ascii2Hex(ch1);
	j = Ascii2Hex(ch2);
	hexval = i * 16 + j;
	return hexval;
}
/*****************************************************************************************
*  Name        : Ascii2Hex
*  Description :
*  Parameter   : char cha
*  Returns     :
*****************************************************************************************/
U8 Ascii2Hex(char cha)
{
	U8 temp;
	if (cha >= 0x30 && cha <= 0x39)
	{
		temp = cha - 0x30;
	}
	else if (cha >= 'A' && cha <= 'F')
	{
		temp = cha - 'A' + 10;
	}
	else if (cha >= 'a' && cha <= 'f')
	{
		temp = cha - 'a' + 10;
	}
	else
	{
		temp = 255;
	}
	return temp;
}


unsigned char HexToChar(unsigned char bChar)
{
	if ((bChar >= 0x30) && (bChar <= 0x39))
	{
		bChar -= 0x30;
	}
	else if ((bChar >= 0x41) && (bChar <= 0x46)) // Capital
	{
		bChar -= 0x37;
	}
	else if ((bChar >= 0x61) && (bChar <= 0x66)) //littlecase
	{
		bChar -= 0x57;
	}
	else
	{
		bChar = 0xff;
	}
	return bChar;
}

/*****************************************************************************************
*  Name        : CalcCRC
*  Description :
*  Parameter   : U8 data[], int length
*  Returns     :
*****************************************************************************************/
void CalcCRC(U8 data[], int length)
{
	int i;
	for (i = 0; i < length; i++)
	{
		tmp = tmp + data[i];
	} /* result of above calculation shall be: tmp=0x1F0 */ /* Since crc is char type, the high U8 of tmp is ignored and crc shall be 1‘s
															complement of low U8 */
}
/*****************************************************************************************
*  Name        : CopyStringToBuffer
*  Description :
*  Parameter   : char Str[], char Buf[], int Offset, int Len
*  Returns     :
*****************************************************************************************/
void CopyStringToBuffer(char Str[], char Buf[], int Offset, int Len)
{
	int i;
	for (i = 0; i < Len; i++)
	{
		Buf[i] = Str[i + Offset];
	}
	Buf[i] = 0;
}
/*****************************************************************************************
*  Name        : ConvertAsciiStringToHexArray
*  Description :
*  Parameter   : char Data[], int length
*  Returns     :
*****************************************************************************************/
void ConvertAsciiStringToHexArray(char Data[], int length)
{
	int i, j;
	j = 0;
	for (i = 0; i < length - 1;)
	{
		HexDataArray[j] = AsciiToHex(Data[i], Data[i + 1]);
		i += 2;
		j++;

	}
	HexDataArray[j] = 0;
}
/*****************************************************************************************
*  Name        : S19checkOneLineChecksum
*  Description :
*  Parameter   : U8 Data[], int length
*  Returns     :
*****************************************************************************************/
U8 S19checkOneLineChecksum(U8 Data[], int length)
{
	int j;
	U8 tem_checksum;
	U8 Datachecksum;
	tem_checksum = 0;

	for (j = 0; j < length - 1; j++)
	{
		tem_checksum += Data[j];
	}

	Datachecksum = Data[j];//get cs
	tem_checksum = 0xFF - tem_checksum;//calculate cs

	//printf("=====S19checkOneLineChecksum === %x\n", tem_checksum);
	if (Datachecksum == tem_checksum)//compare cs
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
/*****************************************************************************************
*  Name        : HexCheckOneLineCheckSum
*  Description :
*  Parameter   : U8 Data[], int length
*  Returns     :
*****************************************************************************************/
U8 HexCheckOneLineCheckSum(U8 Data[], int length)
{
	int j;
	U8 tem_checksum;
	U8 Datachecksum;
	tem_checksum = 0;
	for (j = 0; j < length - 1; j++)
	{
		tem_checksum += Data[j];
	}
	Datachecksum = Data[j];
	tem_checksum = 0xFF - tem_checksum + 1;
	// write("the cal checksum is %x, the data checksum is %x",tem_checksum,Datachecksum);
	if (Datachecksum == tem_checksum)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}
/*****************************************************************************************
*  Name        : CalcChecksum
*  Description :
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void CalcChecksum(U8 data[], int length)
{
	int i;
	for (i = 0; i < length; i++)
	{
		tmp = tmp + data[i];
	}
}
/*****************************************************************************************
*  Name        : CalculateSectorDataCrc16
*  Description :
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
U32 CalculateSectorDataCrc16(void)
{
	U16 i = 0;
	int datalength;
	U16 filechecksum;
	U8 DocumentNameSub[200];
	filechecksum = 0xFFFF;
	for (i = 1; i < DocumentNameLength; i++)
	{
		DocumentNameSub[i - 1] = DocumentName[i];
	}
	//filechecksum = crc16(filechecksum,DocumentNameSub,DocumentNameLength-1);
	for (i = 0; i < (DataTotalLen / MaxDataLengh); i++)
	{
		filechecksum = crc16(filechecksum, DataStr[i], 192);
	}
	datalength = DataTotalLen % MaxDataLengh;
	filechecksum = crc16(filechecksum, DataStr[i], datalength);
	return filechecksum;
}
/*****************************************************************************************
*  Name        : crc16
*  Description :
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
U32 crc16(U32 Incrc, U8 buffer[], U32 size)
{
	U32 i;
	U16 tmp;
	U16 crc;
	crc = Incrc;

	for (i = 0; i < size; i++)
	{
		tmp = (crc >> 8) ^ buffer[i];

		crc = (crc << 8) ^ crctab[tmp];
	}
	return crc;
}

void Spy_EveryMessage(GenericMessage *p_Msg)
{
	// TODO: add something you want to do for every message
}
void Spy_EveryLoop(unsigned int uiCurrentTime)
{
	// TODO: add something you want to do every millisecond
}

void Spy_ErrorState(int iNetwork, int iTxErrorCount, int iRxErrorCount, int iErrorBitfield)
{

}

void Spy_ErrorFrame(int iNetwork, int iTxErrorCount, int iRxErrorCount, int iErrorBitfield)
{

}

void Spy_Stopped()
{
	// TODO: add stopped code
	Diag_Status = DiagNone;
}

void Spy_KeyPress(int iKey, int iCTRLPressed, int iALTPressed)
{
	// TODO: add key handler code
}
void Spy_Started()
{
	// TODO: add started code
	upgrade_finish = 0;
	AS_AppLed_Set(AS_AppLed_$$_off);
	AS_BootLed_Set(AS_AppLed_$$_off);
	AS_upgradeTime_Set(0);
	Inquire_System_State_Req();
}

void GetSoftwareVersion_Rep(void)
{
	Diag_Status = GetSoftwareVersion;

	gTxDataBuffer[0] = 0x22;
	gTxDataBuffer[1] = 0x10;
	gTxDataBuffer[2] = 0x01;
	txCount = 3;

	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}


void GetSoftwareVersion_Resp(void)
{
	U8 i = 0;

	if (softwareVersionRespCnt == 0)
	{
		softversion[softwareVersionoffset++] = gRxDataBuffer[4];
		softversion[softwareVersionoffset++] = gRxDataBuffer[5];
		softversion[softwareVersionoffset++] = gRxDataBuffer[6];
	}
	else
	{
		for (i = 0; i < 7; i++)
		{
			softversion[softwareVersionoffset++] = gRxDataBuffer[i];
		}
	}

	softwareVersionRespCnt++;

	if (softwareVersionRespCnt >= 4)
	{
		AS_AppGetMCUVersion_SetText(softversion);
	}
	else
	{
		SendFC();
	}


#if 0
	printf("gRxDataBuffer[0]==%d ", gRxDataBuffer[0]);
	printf("gRxDataBuffer[0]==%d ", gRxDataBuffer[1]);
	printf("gRxDataBuffer[0]==%d ", gRxDataBuffer[2]);
	printf("gRxDataBuffer[0]==%d ", gRxDataBuffer[3]);
	printf("gRxDataBuffer[0]==%d ", gRxDataBuffer[4]);
	printf("gRxDataBuffer[0]==%d ", gRxDataBuffer[5]);
	printf("gRxDataBuffer[0]==%d ", gRxDataBuffer[6]);
	printf("\n");
#endif    
}

void Inquire_System_State_Req(void)
{
	Diag_Status = Inquire_System_State;

	gTxDataBuffer[0] = 0x27;
	gTxDataBuffer[1] = 0x03;
	txCount = 2;

	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}


void SpyAppSig_AS_AppSystemStateInquire_Resp(void)
{
#if 0
	printf("gRxDataBuffer[0]==%x\n", gRxDataBuffer[0]);
	printf("gRxDataBuffer[1]==%x\n", gRxDataBuffer[1]);
	printf("gRxDataBuffer[2]==%x\n", gRxDataBuffer[2]);
#endif
	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x27) && (gRxDataBuffer[2] == 0x11))
	{
		AS_AppLed_Set(AS_AppLed_$$_on);
		AS_BootLed_Set(AS_BootLed_$$_off);
	}
	else if ((gRxDataBuffer[0] == 0x67) && (gRxDataBuffer[1] == 0x03))
	{
		AS_AppLed_Set(AS_AppLed_$$_off);
		AS_BootLed_Set(AS_BootLed_$$_on);
	}

	GetSoftwareVersion_Rep();

}



/*****************************************************************************************
*  Name        : Spy_BeforeStarted
*  Description : init message before vspy start
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void Spy_BeforeStarted()
{
	// TODO: add before started code
	TX_Diag_Func_Rx_HS_CAN_Init(&Diag_Func_Request);
	TX_AVM_Phys_Diag_Rx_Req_to_DVD_HS_CAN_Init(&Diag_Phys_Request);
}

/*****************************************************************************************
*  Name        : Spy_Main
*  Description : init variables and init application signals defined in vspy
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void Spy_Main()
{
	fileNumber = 0;
	curfileNumber = 0;

	AS_AppFileNumber_Set(fileNumber);
	AS_AppCurFileNumber_Set(curfileNumber);

	while (1);
}
void SpyTmr_Timer_1ms_Entry()
{
	AS_upgradeTime_Set(CurrentTotalLen);

	if (upgrade_finish == 1)
	{
		Tmr_Timer_1ms_Entry_Enable_Set(0);
	}
	else
	{
		//printf("timer over\n");
	}
}

#if 0
void Tmr_Timer_1ms_Entry_Set(double dValue)
{
	CM_GetSetValue(g_uiHandle, CM_GETSET_SET_TMR_VALUE, TMR_Timer_2ms_Entry_Index, &dValue);
}
double Tmr_Timer_1ms_Entry_Get()
{
	double dTemp;
	CM_GetSetValue(g_uiHandle, CM_GETSET_GET_TMR_VALUE, TMR_Timer_2ms_Entry_Index, &dTemp);
	return dTemp;
}
void Tmr_Timer_1ms_Entry_Enable_Set(int iValue)
{
	CM_GetSetValue(g_uiHandle, CM_GETSET_SET_TMR_ENABLE, TMR_Timer_2ms_Entry_Index, &iValue);
}
int Tmr_Timer_1ms_Entry_Enable_Get()
{
	int iTemp;
	CM_GetSetValue(g_uiHandle, CM_GETSET_GET_TMR_ENABLE, TMR_Timer_2ms_Entry_Index, &iTemp);
	return iTemp;
}
void Tmr_Timer_1ms_Entry_SetPeriod(double dValue)
{
	CM_GetSetValue(g_uiHandle, CM_GETSET_SET_TMR_PERIOD, TMR_Timer_2ms_Entry_Index, &dValue);
}
int Tmr_Timer_1ms_Entry_GetTimeToElapse()
{
	int iTemp;
	CM_GetSetValue(g_uiHandle, CM_GETSET_GET_TMR_TIME_TO_ELAPSE, TMR_Timer_2ms_Entry_Index, &iTemp);
	return iTemp;
}
#endif
/*****************************************************************************************
*  Name        : SpyAppSig_AS_AppStartDownload
*  Description : start button in graphical panels vspy and send extended session command
*  Parameter   : dNewValue
*  Returns     : none
*****************************************************************************************/
void SpyAppSig_AS_AppStartDownload(double dNewValue)
{
	if (downloadType == DOWNLOAD_NONE)
	{
		//return;
	}
	else
	{
		/*do nothing;*/
	}

	updateflag = 0;
	LastTransferBlockSize = 0;
	upgrade_finish = 0;

	CurrentTotalLen = 0;

	softwareVersionoffset = 0;
	softwareVersionRespCnt = 0;

	Tmr_Timer_1ms_Entry_Enable_Set(1);//start timer    

	DiagStartExtendedSession();//wait passive response
}

void SpyAppSig_AS_AppRestartSystem(double dNewValue)
{
	// TODO: Add Event Code
	updateflag = 1;
	DiagStopResetMcu();
}


/*****************************************************************************************
*  Name        : SpyAppSig_AS_AppSourceFile
*  Description : read update file button in graphical panels vspy
*  Parameter   : dNewValue
*  Returns     : none
*****************************************************************************************/
void SpyAppSig_AS_AppSourceFile(double dNewValue)
{
	struct _finddata_t fa;
	long fHandle;
	int i = 0;
	char fileName[MAX_PATH];//MAX_PATH is printed 260
	char extName[10];

	fileNumber = 0;
	curfileNumber = 0;
	DataCurrPos = 0;
	DataCurrIndex = 0;
	DataCurrAddr = 0;
	DataTotalLen = 0;
	DataBlockIndex = 0;
	DataPageAddr = 0;

	crc = 0x00;
	tmp = 0x00;

	for (i = 0; i < 200; i++)
	{
		sourceFileFolder[i] = 0;
		sourceFileScan[i] = 0;
	}

	AS_AppSourceFile_GetText(sourceFile);//get file path:sourceFile is D:\uidp5020\Desktop\dsp_update\vicp.bin

	for (i = strlen(sourceFile); i >= 0; i--)//look forward
	{
		if (sourceFile[i] == '\\')
		{
			break;
		}

		if (sourceFile[i] == '.')// get file extend name
		{
			strcpy_s(extName, sizeof(extName), sourceFile + i);
		}
	}

	if (strcmp(extName, ".s19") == 0 || strcmp(extName, ".bin") == 0)//update which according extend name
	{
		downloadType = MCU_DOWNLOAD;
		printf("S32R274 download\n");

	}
	else if (strcmp(extName, ".ldr") == 0)
	{
		downloadType = DSP_DOWNLOAD;
		printf("DSP download\n");
	}
	else
	{
		downloadType = DOWNLOAD_NONE;
		printf("file format error\n");
	}

	strncpy(fileName, sourceFile + i + 1, strlen(sourceFile) - i - 1);//store file name
	fileName[strlen(sourceFile) - i - 1] = '\0';

	strncpy(sourceFileFolder, sourceFile, i + 1);//sourceFile is D:\uidp5020\Desktop\dsp_update\vicp.bin
	strncpy(sourceFileScan, sourceFile, i + 1);
	//  strncpy(logFile, sourceFile, i + 1);
	printf("Current work dir->%s\n", sourceFileFolder);/*D:\uidp5020\Desktop\dsp_update\*/
	strcat(sourceFileScan, "*");
	strcat(sourceFileScan, extName);
#if 0
	strcat(logFile, "achieve");
	mkdir(logFile);
	strcat(logFile, "\\log.txt");
#endif
	if ((fHandle = _findfirst(sourceFileScan, &fa)) == -1L)//find *.bin
	{
		printf("Can't find file, please note file extend name!\n");
		return;
	}
	else
	{
		do
		{
			strcpy(sourcefiles[fileNumber], sourceFileFolder);
			strcat(sourcefiles[fileNumber], fa.name);//fa.name is vicp.bin

			if (strcmp(fileName, fa.name) == 0)
			{
				curfileNumber = fileNumber;
			}
#if 0
			strncpy(sourceFileMove[fileNumber], sourceFileFolder, i + 1);
			strcat(sourceFileMove[fileNumber], "achieve\\");
			strcat(sourceFileMove[fileNumber], fa.name);
			printf("Find file: %s\n", sourcefiles[fileNumber]);
			printf("Move file: %s\n", sourceFileMove[fileNumber]);
#endif
			fileNumber++;
		} while (_findnext(fHandle, &fa) == 0);
	}
	_findclose(fHandle);

	AS_AppFileNumber_Set(fileNumber);
	AS_AppCurFileNumber_Set(curfileNumber + 1);//show file number in vspy3 graphical panels

	ReadFileData(curfileNumber);//curfileNumber is 0
	printf("loaded file is %s\n", sourcefiles[curfileNumber]);
}

/*****************************************************************************************
*  Name        : SpyMsg_MG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN
*  Description : SpyMsg_MG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN message event interface
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void SpyMsg_MG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN(MG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN *pMG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN)
{
	//Sleep(10);
	// TODO: Add Event Code
	gRxDataBuffer[0] = pMG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN->Byte1_raw;
	gRxDataBuffer[1] = pMG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN->Byte2_raw;
	gRxDataBuffer[2] = pMG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN->Byte3_raw;
	gRxDataBuffer[3] = pMG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN->Byte4_raw;
	gRxDataBuffer[4] = pMG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN->Byte5_raw;
	gRxDataBuffer[5] = pMG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN->Byte6_raw;
	gRxDataBuffer[6] = pMG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN->Byte7_raw;
#if 0
	printf("received gRxDataBuffer1======%x\n", gRxDataBuffer[0]);
	printf("received gRxDataBuffer2======%x\n", gRxDataBuffer[1]);
	printf("received gRxDataBuffer3======%x\n", gRxDataBuffer[2]);
	printf("received gRxDataBuffer4======%x\n", gRxDataBuffer[3]);
	printf("received gRxDataBuffer5======%x\n", gRxDataBuffer[4]);
	printf("received gRxDataBuffer6======%x\n", gRxDataBuffer[5]);
	printf("received gRxDataBuffer7======%x\n", gRxDataBuffer[6]);
	printf("received gRxDataBuffer8======%x\n", gRxDataBuffer[7]);
	printf("!!!!!before send received fc frame!!!!\n");
#endif
	/*deal flow frame*/
	if (pMG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN->Byte0_raw == 0x30)
	{
		wait30Freq = pMG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN->Byte1_raw;
		minSendInterval = pMG_AVM_Phys_Diag_Tx_Resp_From_DVD_HS_CAN->Byte2_raw;

		SendDataAtFhysicalConnector_SecondPart(gTxDataBuffer, txCount);
		return;
	}

	FunDiagRequest();
	DiagMessageResp();
}
/*****************************************************************************************
*  Name        : FunDiagRequest
*  Description : send request message
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void FunDiagRequest(void)
{
	switch (Diag_Status)
	{
	case StartExtendedSession:
		DiagStartExtendedSessionResp();
		break;
	case DisableDTCstorage:
		DiagDisableDTCstorageResp();
		break;
	case DisableNMAndCommunicationMessage:
		DiagDisableNMAndCommunicationMessageResp();
		break;
	case ChangeToProgrammingSession:
		DiagChangeToProgrammingSessionResp();
		break;
	case ChangeToExtendedSession:
		DiagChangeToExtendedSessionResp();
		break;
	case EnableNMAndCommunicationMessage:
		DiagEnableNMAndCommunicationMessageResp();
		break;
	case EnableDTCstorage:
		DiagEnableDTCstorageResp();
		break;
	case ClearAllDTC:
		DiagClearAllDTCResp();
		break;
	case ChangeToDefaultSession:
		DiagChangeToDefaultSessionResp();
		break;
	case StartMCUDownload:
		DiagStartMCUDownloadResp();
		break;
	case StartWriteFlagMCUDownload:
		DiagStartWriteFlagMCUDownloadResp();
		break;
	case SetMCUDate:
		SetMCUDateResp();
		break;
	default:
		break;
	}
}
/*****************************************************************************************
*  Name        : DiagStopResetMcu
*  Description : deal response message
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagMessageResp(void)
{
	switch (Diag_Status)
	{
	case RequestResetMcuPre:
		DiagResetMcuPreResp();
		break;
	case StartReProgramSection:
		DiagStartReprogramSectionResp();
	case RequestSecuritySeed:
		DiagRequestSecuritySeedResp();
		break;
	case SendSecurityKey:
		DiagSendSecurityKeyResp();
		break;
	case StartEraseMemoryProcedure:
		DiagEraseFlashSector_StartRoutineResps();
		break;
	case RequestEraseMemoryProcedureResult:
		DiagEraseFlashSector_RequestRoutineResultResps();
		break;
	case StopEraseMemoryProcedure:
		DiagEraseFlashSector_StopRoutineResps();
	case RequestDownload:
		DiagRequestDownloadDataResp();
		break;
	case TransferDataBlock:
		DiagTransferDataResp();
		break;
	case StopTransferData:
		DiagStopTransferDataResp();
		break;
	case StartCheckProgramDependency:
		DiagCheckProgramDependency_StartRoutineResp();
		break;
	case RequestCheckProgramDependencyResult:
		DiagCheckProgramDependency_RequestRoutineResultResp();
		break;
	case StopCheckProgramDependency:
		DiagCheckProgramDependency_StopRoutineResp();
		break;
	case StartCheckApplicationProgramValidation:
		DiagCheckApplicationProgramValidation_StartRoutinResp();
		break;
	case RequestCheckApplicationProgramValidationResult:
		DiagCheckApplicationProgramValidation_RequestRoutineResultResp();
		break;
	case StopCheckApplicationProgramValidation:
		DiagCheckApplicationProgramValidation_StopRoutineResp();
		break;
	case RequestResetMcu:
		DiagResetMcuResp();
		break;
	case RequestStopResetMcu:
		DiagStopResetMcuResp();
		break;
	case GetSoftwareVersion:
		GetSoftwareVersion_Resp();
		break;
	case Inquire_System_State:
		SpyAppSig_AS_AppSystemStateInquire_Resp();
		break;
	default:
		break;
	}
}

/*****************************************************************************************
*  Name        : DiagStopResetMcu
*  Description : send 11 01 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagStopResetMcu(void)
{
	Diag_Status = RequestStopResetMcu;
	gTxDataBuffer[0] = 0x11;
	gTxDataBuffer[1] = 0x01;
	txCount = 2;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);;
}
/*****************************************************************************************
*  Name        : DiagStopResetMcuResp
*  Description : deal 51 response
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagStopResetMcuResp(void)
{
	if ((gRxDataBuffer[0] == 0x51) && (gRxDataBuffer[1] == 0x01))
	{
		;
	}
}


/*****************************************************************************************
*  Name        : DiagStartMCUDownload
*  Description : send 2E 40 service command
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagStartMCUDownload(void)
{
	Diag_Status = StartMCUDownload;
	gTxDataBuffer[0] = 0x2E;
	gTxDataBuffer[1] = 0x40;
	gTxDataBuffer[2] = 0x00;
	gTxDataBuffer[3] = 0x01;
	txCount = 4;
	SendDataAtFunctionalConnector(gTxDataBuffer, txCount);
}


/*****************************************************************************************
*  Name        : DiagStartMCUDownloadResp
*  Description : dela 2E 40 response
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagStartMCUDownloadResp(void)
{
	if ((gRxDataBuffer[0] == 0x6E) && (gRxDataBuffer[1] == 0x40) &&
		(gRxDataBuffer[2] == 0x00))
	{
		DiagStartWriteFlagMCUDownload();
	}
}



/*****************************************************************************************
*  Name        : DiagStartExtendedSession
*  Description : send extended seession command use Function Address message
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagStartExtendedSession(void)
{
	Diag_Status = StartExtendedSession;

	gTxDataBuffer[0] = 0x10;
	gTxDataBuffer[1] = 0x03;
	txCount = 2;

	SendDataAtFunctionalConnector(gTxDataBuffer, txCount);
}

/*****************************************************************************************
*  Name        : DiagStartExtendedSessionResp
*  Description : deal 10 03 response
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagStartExtendedSessionResp(void)
{
	if ((gRxDataBuffer[0] == 0x50) && (gRxDataBuffer[1] == 0x03))
	{
		DiagDisableDTCstorage();
	}

}
/*****************************************************************************************
*  Name        : DiagDisableDTCstorage
*  Description : send 85 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagDisableDTCstorage(void)
{
	Diag_Status = DisableDTCstorage;
	gTxDataBuffer[0] = 0x85;
	gTxDataBuffer[1] = 0x02;
	txCount = 2;
	SendDataAtFunctionalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagDisableDTCstorageResp
*  Description : deal 85 response
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagDisableDTCstorageResp(void)
{
	if ((gRxDataBuffer[0] == 0xC5) && ((gRxDataBuffer[1] == 0x02)))
	{
		if (gRxDataBuffer[2] == 0x44)
		{
			DiagChangeToExtendedSession();/*upgrade in boot*/
		}
		else
		{
			DiagDisableNMAndCommunicationMessage();
		}
	}
}
/*****************************************************************************************
*  Name        : DiagDisableNMAndCommunicationMessage
*  Description : send 28 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagDisableNMAndCommunicationMessage(void)
{
	Diag_Status = DisableNMAndCommunicationMessage;
	gTxDataBuffer[0] = 0x28;
	gTxDataBuffer[1] = 0x03;
	gTxDataBuffer[2] = 0x03;
	txCount = 3;
	SendDataAtFunctionalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagDisableNMAndCommunicationMessageResp
*  Description : deal response after send 28 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagDisableNMAndCommunicationMessageResp(void)
{
	if ((gRxDataBuffer[0] == 0x68) && (gRxDataBuffer[1] == 0x03))
	{
		DiagStartWriteFlagMCUDownload();//send write upgrade flag command
	}
}

/*****************************************************************************************
*  Name        : DiagStartWriteFlagMCUDownload
*  Description : send 2E 40 service command
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagStartWriteFlagMCUDownload(void)
{
	Diag_Status = StartWriteFlagMCUDownload;
	gTxDataBuffer[0] = 0x2E;
	gTxDataBuffer[1] = 0x40;
	gTxDataBuffer[2] = 0x01;
	gTxDataBuffer[3] = 0x01;
	txCount = 4;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}

/*****************************************************************************************
*  Name        : DiagStartWriteFlagMCUDownloadResp
*  Description : dela 2E 40 response
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagStartWriteFlagMCUDownloadResp(void)
{
	if ((gRxDataBuffer[0] == 0x6E) && (gRxDataBuffer[1] == 0x40) &&
		(gRxDataBuffer[2] == 0x01))
	{
		DiagStartReprogramSection();
	}
}

/*****************************************************************************************
*  Name        : DiagStartReprogramSection
*  Description : send 10 02 service command
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagStartReprogramSection(void)
{
	Diag_Status = StartReProgramSection;
	gTxDataBuffer[0] = 0x10;
	gTxDataBuffer[1] = 0x02;
	txCount = 2;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}

/*****************************************************************************************
*  Name        : DiagStartReprogramSectionResp
*  Description : deal 10 02 response
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagStartReprogramSectionResp(void)
{
	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x10) && (gRxDataBuffer[2] == 0x78))
	{
		//Sleep(5000);
		//DiagChangeToExtendedSession();
	}
	else if ((gRxDataBuffer[0] == 0x51) && (gRxDataBuffer[1] == 0x01))/*auto response 51 01 when can component init finish after mcu restart*/
	{
		DiagChangeToExtendedSession();
	}
}
/*****************************************************************************************
*  Name        : DiagChangeToExtendedSession
*  Description : send extended session command
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagChangeToExtendedSession(void)
{
	AS_AppLed_Set(AS_AppLed_$$_off);
	AS_BootLed_Set(AS_BootLed_$$_on);

	Diag_Status = ChangeToExtendedSession;
	gTxDataBuffer[0] = 0x10;
	gTxDataBuffer[1] = 0x03;
	txCount = 2;
	SendDataAtFunctionalConnector(gTxDataBuffer, txCount);
}

/*****************************************************************************************
*  Name        : DiagChangeToExtendedSessionResp
*  Description : deal response after send extended session command
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagChangeToExtendedSessionResp(void)
{
	if ((gRxDataBuffer[0] == 0x50) && (gRxDataBuffer[1] == 0x03))
	{
		DiagChangeToProgrammingSession();
	}
}

/*****************************************************************************************
*  Name        : DiagChangeToProgrammingSession
*  Description : send Programming session command
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagChangeToProgrammingSession(void)
{
	Diag_Status = ChangeToProgrammingSession;
	gTxDataBuffer[0] = 0x10;
	gTxDataBuffer[1] = 0x02;
	txCount = 2;
	SendDataAtFunctionalConnector(gTxDataBuffer, txCount);
}

/*****************************************************************************************
*  Name        : DiagChangeToProgrammingSessionResp
*  Description : deal response after send Programming session command
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagChangeToProgrammingSessionResp(void)
{
	if ((gRxDataBuffer[0] == 0x50) && (gRxDataBuffer[1] == 0x02))
	{
		DiagRequestSecuritySeed();
	}
	else if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x10))
	{
		DiagRequestSecuritySeed();
	}
}
/*****************************************************************************************
*  Name        : DiagRequestSecuritySeed
*  Description : send 27 sucerity access service command
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagRequestSecuritySeed(void)
{
	Diag_Status = RequestSecuritySeed;

	gTxDataBuffer[0] = 0x27;

	if (downloadType == MCU_DOWNLOAD)
	{
		gTxDataBuffer[1] = 0x03;
	}
	else
	{
		gTxDataBuffer[1] = 0x04;
	}

	txCount = 2;

	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}

/*****************************************************************************************
*  Name        : DiagRequestSecuritySeedResp
*  Description : deal 27 service  response
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagRequestSecuritySeedResp(void)
{
	if (downloadType == MCU_DOWNLOAD)
	{
		if ((gRxDataBuffer[0] == 0x67) && (gRxDataBuffer[1] == 0x03))
		{
			if ((gRxDataBuffer[2] == 0x22) && (gRxDataBuffer[3] == 0x00))
			{
				DiagEraseFlashSector_StartRoutine();
			}
			else
			{
				SecuritySeed[0] = gRxDataBuffer[2];
				SecuritySeed[1] = gRxDataBuffer[3];
				SecuritySeed[2] = gRxDataBuffer[4];
				SecuritySeed[3] = gRxDataBuffer[5];
				//printf("SecuritySeed0======%x\n", SecuritySeed[0]);
				//printf("SecuritySeed1======%x\n", SecuritySeed[1]);
				//printf("SecuritySeed2======%x\n", SecuritySeed[2]);
				//printf("SecuritySeed3======%x\n", SecuritySeed[3]);

				DiagSendSecurityKey_MCU();
			}
		}
		else
		{
			//DiagSendSecurityKey_MCU();
		}
	}
	else
	{
		if ((gRxDataBuffer[0] == 0x67) && (gRxDataBuffer[1] == 0x03))
		{
			if ((gRxDataBuffer[2] == 0x00) && (gRxDataBuffer[3] == 0x00))
			{
				DiagEraseFlashSector_StartRoutine();
			}
			else
			{
				SecuritySeed[0] = gRxDataBuffer[2];
				SecuritySeed[1] = gRxDataBuffer[3];
				printf("SecuritySeed0======%x\n", SecuritySeed[0]);
				printf("SecuritySeed1======%x\n", SecuritySeed[1]);

				DiagSendSecurityKey();
			}
		}
	}
}
/*****************************************************************************************
*  Name        : DiagSendSecurityKey_MCU
*  Description : send security key to ecu
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagSendSecurityKey_MCU(void)
{
	Diag_Status = SendSecurityKey;

	calcKey_MCU(SecuritySeed);

	gTxDataBuffer[0] = 0x27;
	gTxDataBuffer[1] = 0x04;
	gTxDataBuffer[2] = SecurityKey[0];
	gTxDataBuffer[3] = SecurityKey[1];
	gTxDataBuffer[4] = SecurityKey[2];
	gTxDataBuffer[5] = SecurityKey[3];
	txCount = 6;

	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagSendSecurityKeyResp
*  Description : deal response after send security key to ecu
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagSendSecurityKeyResp(void)
{
	if (downloadType == MCU_DOWNLOAD)
	{
		if ((gRxDataBuffer[0] == 0x67) && (gRxDataBuffer[1] == 0x04))
		{
			//SetMCUDateReq();
			DiagEraseFlashSector_StartRoutine();//send dataAddress and dataLength
		}
	}
	else
	{
		if ((gRxDataBuffer[0] == 0x67) && (gRxDataBuffer[1] == 0x01))
		{
			DiagEraseFlashSector_StartRoutine();
		}
	}
}

/*****************************************************************************************
*  Name        : DiagResetMcuPre
*  Description : send 11 01 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagResetMcuPre(void)
{
	Diag_Status = RequestResetMcuPre;
	gTxDataBuffer[0] = 0x11;
	gTxDataBuffer[1] = 0x01;
	txCount = 2;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagResetMcuPreResp
*  Description : deal response after send 11 01 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagResetMcuPreResp(void)
{
	if ((gRxDataBuffer[0] == 0x51) && (gRxDataBuffer[1] == 0x01))
	{
		Sleep(2000);
		DiagRequestSecuritySeed();//execute 27 service , set proper session
	}
}


/*****************************************************************************************
*  Name        : SetMCUDateReq
*  Description : send 2e service command
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void SetMCUDateReq(void)
{
	SYSTEMTIME st;
	GetLocalTime(&st);

	Diag_Status = SetMCUDate;

	gTxDataBuffer[0] = 0x2E;
	gTxDataBuffer[1] = 0xF1;
	gTxDataBuffer[2] = 0x99;
	gTxDataBuffer[3] = 0x20;

	gTxDataBuffer[4] = hex2bcd(st.wYear - 2000);
	gTxDataBuffer[5] = hex2bcd(st.wMonth);
	gTxDataBuffer[6] = hex2bcd(st.wDay);
	txCount = 7;

	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}

/*****************************************************************************************
*  Name        : SetMCUDateResp
*  Description : deal response after send 2e service command
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void SetMCUDateResp(void)
{
	if ((gRxDataBuffer[0] == 0x6E) && (gRxDataBuffer[1] == 0xF1) && (gRxDataBuffer[2] == 0x99))
	{
		DiagEraseFlashSector_StartRoutine();//send dataAddress and dataLength
	}
	else
	{
		/*do thing*/
	}
}

void DiagSendSecurityKey(void)
{
	Diag_Status = SendSecurityKey;
	calcKey(SecuritySeed);
	gTxDataBuffer[0] = 0x27;
	gTxDataBuffer[1] = 0x04;
	gTxDataBuffer[2] = SecurityKey[0];
	gTxDataBuffer[3] = SecurityKey[1];
	txCount = 4;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}

/*****************************************************************************************
*  Name        : DiagEraseFlashSector_StopRoutine
*  Description : send 31 service.
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagEraseFlashSector_StopRoutine(void)
{
	Diag_Status = StopEraseMemoryProcedure;
	gTxDataBuffer[0] = 0x31;
	gTxDataBuffer[1] = 0x02;
	gTxDataBuffer[2] = 0xff;
	gTxDataBuffer[3] = 0x00;

	txCount = 4;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagEraseFlashSector_StopRoutineResps
*  Description : deal response after send 31 service.
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagEraseFlashSector_StopRoutineResps(void)
{
	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x31) && (gRxDataBuffer[2] == 0x78))
	{
		;
	}
	else if ((gRxDataBuffer[0] == 0x71) && (gRxDataBuffer[1] == 0x02) && (gRxDataBuffer[2] == 0xFF) && (gRxDataBuffer[3] == 0x00) && (gRxDataBuffer[4] == 0x04))
	{
		DiagRequestDownloadData();

	}
}

/*****************************************************************************************
*  Name        : DiagStopTransferData
*  Description : send 37 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagStopTransferData(void)
{
	Diag_Status = StopTransferData;
	gTxDataBuffer[0] = 0x37;
	txCount = 1;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagStopTransferDataResp
*  Description : deal response after send 37 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagStopTransferDataResp(void)
{
	if (gRxDataBuffer[0] == 0x77)
	{
		DiagCheckProgramDependency_StartRoutine();
	}
}
/*****************************************************************************************
*  Name        : DiagCheckProgramDependency_StartRoutine
*  Description : deal response after send 37 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagCheckProgramDependency_StartRoutine(void)
{
	U32 file_checksum = 0;
	U32 i = 0, j = 0, k = 0, m = 0;
	U32 middleTemp = 0;
	unsigned char *bData = NULL;

	Diag_Status = StartCheckProgramDependency;

	if (downloadType == MCU_DOWNLOAD)
	{
		gTxDataBuffer[0] = 0x31;
		gTxDataBuffer[1] = 0x01;
		gTxDataBuffer[2] = 0xff;
		gTxDataBuffer[3] = 0x01;

		//file_checksum = Calculate_Crc32((U8 *)DataStr, DataTotalLen);

		bData = (char *)DataStr;

		for (i = 0; i < DataTotalLen / 4; i++)
		{
			middleTemp = DescMake32Bit(bData[i * 4], bData[i * 4 + 1], \
				bData[i * 4 + 2], bData[i * 4 + 3]);
			file_checksum += middleTemp;
#if 0           
			if (m < 30)
			{
				m++;
				printf("middleTemp = %x\n", middleTemp);
			}



			j++;
			if ((j % 128 == 0) && (k < 10))
			{
				k++;
				printf("%x\n", file_checksum);
			}
#endif            
		}

		printf("file_checksum======%x\n", file_checksum);
		printf("DataTotalLen===%x\n", DataTotalLen);
		gTxDataBuffer[4] = (U8)(file_checksum >> 24);
		gTxDataBuffer[5] = (U8)(file_checksum >> 16);
		gTxDataBuffer[6] = (U8)(file_checksum >> 8);
		gTxDataBuffer[7] = (U8)(file_checksum);

		txCount = 8;
	}
	else
	{
		gTxDataBuffer[0] = 0x31;
		gTxDataBuffer[1] = 0x01;
		gTxDataBuffer[2] = 0xFF;
		gTxDataBuffer[3] = 0x01;

		gTxDataBuffer[4] = (U8)(DataBlockAddr >> 24);
		gTxDataBuffer[5] = (U8)(DataBlockAddr >> 16);
		gTxDataBuffer[6] = (U8)(DataBlockAddr >> 8);
		gTxDataBuffer[7] = (U8)(DataBlockAddr);

		DataBlockLength = DataTotalLen + MaxDataLengh;

		gTxDataBuffer[8] = (U8)(DataBlockLength >> 24);
		gTxDataBuffer[9] = (U8)(DataBlockLength >> 16);
		gTxDataBuffer[10] = (U8)(DataBlockLength >> 8);
		gTxDataBuffer[11] = (U8)(DataBlockLength);

		file_checksum = CalculateSectorDataCrc16();

		gTxDataBuffer[12] = (U8)(file_checksum >> 8);
		gTxDataBuffer[13] = (U8)(file_checksum);

		txCount = 14;
	}

	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagCheckProgramDependency_StartRoutineResp
*  Description : deal response after send 37 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagCheckProgramDependency_StartRoutineResp(void)
{
	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x36) && (gRxDataBuffer[2] == 0x78))
	{
		;
	}
	else if ((gRxDataBuffer[0] == 0x71) && (gRxDataBuffer[1] == 0x01))
	{
		DiagCheckProgramDependency_RequestRoutineResult();
	}
}
/*****************************************************************************************
*  Name        : DiagCheckProgramDependency_RequestRoutineResult
*  Description : deal response after send 37 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagCheckProgramDependency_RequestRoutineResult(void)
{
	Diag_Status = RequestCheckProgramDependencyResult;

	gTxDataBuffer[0] = 0x31;

	if (downloadType == MCU_DOWNLOAD)
	{
		gTxDataBuffer[1] = 0x03;
		gTxDataBuffer[2] = 0xFF;
		gTxDataBuffer[3] = 0x01;
		printf("assignment ok!!!\n");
	}
	else
	{
		gTxDataBuffer[1] = 0x01;
	}

	txCount = 4;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagCheckProgramDependency_RequestRoutineResultResp
*  Description : deal response after send 31 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagCheckProgramDependency_RequestRoutineResultResp(void)
{
	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x36) && (gRxDataBuffer[2] == 0x78))
	{
		;
	}
	else if ((gRxDataBuffer[0] == 0x71) && (gRxDataBuffer[1] == 0x01 || gRxDataBuffer[1] == 0x03) && (gRxDataBuffer[2] == 0xFF) && (gRxDataBuffer[3] == 0x01))
	{
		if (gRxDataBuffer[4] == 0x03)
		{
			DiagCheckProgramDependency_RequestRoutineResult();
		}
		else if (gRxDataBuffer[4] == 0x02)
		{
			DiagCheckProgramDependency_StopRoutine();
		}
		else
		{
			upgrade_finish = 1;
			DiagResetMcu();
		}
	}
}
/*****************************************************************************************
*  Name        : DiagCheckProgramDependency_StopRoutine
*  Description : deal response after send 31 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagCheckProgramDependency_StopRoutine(void)
{
	Diag_Status = StopCheckProgramDependency;
	gTxDataBuffer[0] = 0x31;
	gTxDataBuffer[1] = 0x02;
	gTxDataBuffer[2] = 0xFF;
	gTxDataBuffer[3] = 0x01;

	txCount = 4;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagCheckProgramDependency_StopRoutineResp
*  Description : deal response after send 31 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagCheckProgramDependency_StopRoutineResp(void)
{
	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x36) && (gRxDataBuffer[2] == 0x78))
	{
		;
	}

	else if ((gRxDataBuffer[0] == 0x71) && (gRxDataBuffer[1] == 0x02) && (gRxDataBuffer[2] == 0xFF) && (gRxDataBuffer[3] == 0x01) && (gRxDataBuffer[4] == 0x04))
	{
		if (gRxDataBuffer[5] == 0x01)
		{
			DiagCheckApplicationProgramValidation_StartRoutine();
		}
		else if (gRxDataBuffer[5] == 0x02)
		{
			//not defined
		}
	}
}
/*****************************************************************************************
*  Name        : DiagCheckApplicationProgramValidation_StartRoutine
*  Description : deal response after send 31 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagCheckApplicationProgramValidation_StartRoutine(void)
{
	Diag_Status = StartCheckApplicationProgramValidation;
	gTxDataBuffer[0] = 0x31;
	gTxDataBuffer[1] = 0x01;
	gTxDataBuffer[2] = 0xf0;
	gTxDataBuffer[3] = 0x01;

	file_checksum = CalculateSectorDataCrc16();

	gTxDataBuffer[4] = (U8)(file_checksum >> 8);
	gTxDataBuffer[5] = (U8)(file_checksum);
	txCount = 6;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagCheckApplicationProgramValidation_StartRoutinResp
*  Description : deal response after send 31 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagCheckApplicationProgramValidation_StartRoutinResp(void)
{
	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x36) && (gRxDataBuffer[2] == 0x78))
	{
		;
	}
	else if ((gRxDataBuffer[0] == 0x71) && (gRxDataBuffer[1] == 0x01) && (gRxDataBuffer[2] == 0xf0) && (gRxDataBuffer[3] == 0x01) && (gRxDataBuffer[4] == 0x01))
	{
		DiagCheckApplicationProgramValidation_RequestRoutineResult();
	}
}
/*****************************************************************************************
*  Name        : DiagCheckApplicationProgramValidation_RequestRoutineResult
*  Description : deal response after send 31 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagCheckApplicationProgramValidation_RequestRoutineResult(void)
{
	Diag_Status = RequestCheckApplicationProgramValidationResult;
	gTxDataBuffer[0] = 0x31;
	gTxDataBuffer[1] = 0x03;
	gTxDataBuffer[2] = 0xf0;
	gTxDataBuffer[3] = 0x01;

	txCount = 4;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagCheckApplicationProgramValidation_RequestRoutineResultResp
*  Description : deal response after send 31 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagCheckApplicationProgramValidation_RequestRoutineResultResp(void)
{
	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x36) && (gRxDataBuffer[2] == 0x78))
	{
		;
	}
	else if ((gRxDataBuffer[0] == 0x71) && (gRxDataBuffer[1] == 0x03) && (gRxDataBuffer[2] == 0xf0) && (gRxDataBuffer[3] == 0x01))
	{
		if (gRxDataBuffer[4] == 0x03)
		{
			DiagCheckApplicationProgramValidation_RequestRoutineResult();
		}
		else if (gRxDataBuffer[4] == 0x02)
		{
			DiagCheckApplicationProgramValidation_StopRoutine();
		}
	}
}
/*****************************************************************************************
*  Name        : DiagCheckApplicationProgramValidation_StopRoutine
*  Description : deal response after send 31 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagCheckApplicationProgramValidation_StopRoutine(void)
{
	Diag_Status = StopCheckApplicationProgramValidation;
	gTxDataBuffer[0] = 0x31;
	gTxDataBuffer[1] = 0x02;
	gTxDataBuffer[2] = 0xf0;
	gTxDataBuffer[3] = 0x01;

	txCount = 4;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagCheckApplicationProgramValidation_StopRoutineResp
*  Description : deal response after send 31 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagCheckApplicationProgramValidation_StopRoutineResp(void)
{
	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x36) && (gRxDataBuffer[2] == 0x78))
	{
		;
	}

	else if ((gRxDataBuffer[0] == 0x71) && (gRxDataBuffer[1] == 0x02) && (gRxDataBuffer[2] == 0xf0) && (gRxDataBuffer[3] == 0x01))
	{
		if (gRxDataBuffer[4] == 0x01)
		{
			DiagResetMcu();
		}
		else if (gRxDataBuffer[4] == 0x02)
		{
			DiagResetMcu();
		}
	}
}
/*****************************************************************************************
*  Name        : DiagResetMcu
*  Description : reset mcu after update complete
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagSend3E(void)
{
	gTxDataBuffer[0] = 0x3E;
	gTxDataBuffer[1] = 0x00;
	txCount = 2;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagResetMcu
*  Description : reset mcu after update complete
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagResetMcu(void)
{
	Diag_Status = RequestResetMcu;

	gTxDataBuffer[0] = 0x11;
	gTxDataBuffer[1] = 0x01;
	txCount = 2;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagResetMcuResp
*  Description : send 3E service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagResetMcuResp(void)
{
	if ((gRxDataBuffer[0] == 0x51) && (gRxDataBuffer[1] == 0x01))
	{
		if (downloadType == MCU_DOWNLOAD)
		{
			Sleep(4000);
			printf("test update\n");
			Inquire_System_State_Req();
			//DiagSend3E();
		}
		else
		{
			Sleep(2000);
			//DiagChangeToExtendedSession();
		}
	}
}
/*****************************************************************************************
*  Name        : DiagEraseFlashSector_StartRoutine
*  Description : send 31(rountine control) service command(address and data length)
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagEraseFlashSector_StartRoutine(void)
{
	Diag_Status = StartEraseMemoryProcedure;

	DataBlockLength = DataTotalLen;

	gTxDataBuffer[0] = 0x31;
	gTxDataBuffer[1] = 0x01;
	gTxDataBuffer[2] = 0xff;
	gTxDataBuffer[3] = 0x00;

	if (downloadType == MCU_DOWNLOAD)
	{
		gTxDataBuffer[4] = (U8)(DataBlockAddr >> 24);/*send start address and length*/
		gTxDataBuffer[5] = (U8)(DataBlockAddr >> 16);
		gTxDataBuffer[6] = (U8)(DataBlockAddr >> 8);
		gTxDataBuffer[7] = (U8)(DataBlockAddr);

		gTxDataBuffer[8] = (U8)(DataBlockLength >> 24);
		gTxDataBuffer[9] = (U8)(DataBlockLength >> 16);
		gTxDataBuffer[10] = (U8)(DataBlockLength >> 8);
		gTxDataBuffer[11] = (U8)(DataBlockLength);

		txCount = 12;
	}

	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}

/*****************************************************************************************
*  Name        : DiagEraseFlashSector_StartRoutineResps
*  Description : deal response after send 31(rountine control) service command(address and data length)
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagEraseFlashSector_StartRoutineResps(void)
{
	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x31) && (gRxDataBuffer[2] == 0x78))
	{
		;//deal negative response
	}
	else if ((gRxDataBuffer[0] == 0x71) && (gRxDataBuffer[1] == 0x01) && (gRxDataBuffer[2] == 0xFF))
	{
		if (gRxDataBuffer[4] == 0x01)
		{
			DiagEraseFlashSector_RequestRoutineResult();
		}
		else if (gRxDataBuffer[4] == 0x04)
		{
			DiagRequestDownloadData();
			//DiagCheckProgramDependency_StartRoutine();
		}
	}
}
/*****************************************************************************************
*  Name        : DiagRequestDownloadData
*  Description : send 34(request download) service command(blocksize and data length)
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagRequestDownloadData(void)
{
	Diag_Status = RequestDownload;

	gTxDataBuffer[0] = 0x34;
	gTxDataBuffer[1] = 0x00;
	gTxDataBuffer[2] = 0x44;

	printf("$34 DataBlockAddr is %x\n", DataBlockAddr);

	gTxDataBuffer[3] = (U8)(DataBlockAddr >> 24);
	gTxDataBuffer[4] = (U8)(DataBlockAddr >> 16);
	gTxDataBuffer[5] = (U8)(DataBlockAddr >> 8);
	gTxDataBuffer[6] = (U8)(DataBlockAddr);

	DataBlockLength = DataTotalLen;
	printf("DataTotalLen======%x\n", DataTotalLen);

	gTxDataBuffer[7] = (U8)(DataBlockLength >> 24);
	gTxDataBuffer[8] = (U8)(DataBlockLength >> 16);
	gTxDataBuffer[9] = (U8)(DataBlockLength >> 8);
	gTxDataBuffer[10] = (U8)(DataBlockLength);

	txCount = 11;

	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);

	CurrPos = 0;
	CurrBlock = 0;
}
/*****************************************************************************************
*  Name        : DiagRequestDownloadData
*  Description : deal response after send 34(request download) service command(blocksize and data length)
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagRequestDownloadDataResp(void)
{
	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x34) && (gRxDataBuffer[2] == 0x78))
	{
		;
	}
	else if ((gRxDataBuffer[0] == 0x74) && (gRxDataBuffer[1] == 0x40 || gRxDataBuffer[1] == 0x20))
	{
		if (gRxDataBuffer[1] == 0x40)
		{
			TransferBlockSize = (U32)((int)gRxDataBuffer[5]);
			TransferBlockSize += ((U32)gRxDataBuffer[4] << 8);
			TransferBlockSize += ((U32)gRxDataBuffer[3] << 16);
			TransferBlockSize += ((U32)gRxDataBuffer[2] << 24);
		}
		else if (gRxDataBuffer[1] == 0x20)
		{
			TransferBlockSize = (U32)((int)gRxDataBuffer[3]);/*server request transfer data length 512bytes*/
			TransferBlockSize += ((U32)gRxDataBuffer[2] << 8);
		}

		TransferBlockSize -= 2; ///TODO: to be update

		Repart_flag = 0;
		First_data_Filename = 0;
		CurrentBlockIndex = 0;
		CurrentBlockCnt = 0;
		CurrentTotalLen = 0;

		DiagTransferData();
	}
}

/*****************************************************************************************
*  Name        : DiagTransferData
*  Description : transfer data and send 36 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagTransferData(void)
{
	long i;
	static long Len;

	Diag_Status = TransferDataBlock;

	if (Repart_flag == 0)
	{
		if (CurrentBlockCnt + TransferBlockSize > DataBlockLength)/*TransferBlockSize is 512; DataBlockLength is 684544*/
		{
			Len = DataBlockLength - CurrentBlockCnt;
		}
		else
		{
			Len = TransferBlockSize;
		}

		LastTransferBlockSize = Len;

		CurrentBlockCnt += Len;

		gTxDataBuffer[0] = 0x36;
		gTxDataBuffer[1] = CurrentBlockIndex >> 24;
		gTxDataBuffer[2] = (U8)(CurrentBlockIndex >> 16);
		gTxDataBuffer[3] = (U8)(CurrentBlockIndex >> 8);
		gTxDataBuffer[4] = CurrentBlockIndex & 0xff;

		CurrentTotalLen += Len;

		for (i = 0; i < Len; i++)
		{
			gTxDataBuffer[5 + i] = DataStr[CurrBlock][CurrPos];
			if (++CurrPos >= MaxDataLengh)
			{
				CurrBlock++;
				CurrPos = 0;
			}
		}
	}
	else if (Repart_flag == 1)
	{
		gTxDataBuffer[0] = 0x36;
		gTxDataBuffer[1] = CurrentBlockIndex >> 24;
		gTxDataBuffer[2] = (U8)(CurrentBlockIndex >> 16);
		gTxDataBuffer[3] = (U8)(CurrentBlockIndex >> 8);
		gTxDataBuffer[4] = CurrentBlockIndex & 0xff;

		for (i = 0; i < Len; i++)
		{
			gTxDataBuffer[5 + i] = DataStr[CurrBlock][CurrPos];
			if (++CurrPos >= MaxDataLengh)
			{
				CurrBlock++;
				CurrPos = 0;
			}
		}
	}
	txCount = 5 + Len;

	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagTransferData
*  Description : deal response after transfer data and send 36 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagTransferDataResp(void)
{
	int rem = 0;

	printf("=====Receive CurrentBlockIndex === %d\n", DescMake32Bit(gRxDataBuffer[1], gRxDataBuffer[2], gRxDataBuffer[3], gRxDataBuffer[4]));

	AS_AppProgressBar_Set(CurrentTotalLen * 100 / DataTotalLen);//set progress bar in vspy grahical panel

	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x36) && (gRxDataBuffer[2] == 0x78))
	{
		;
	}
	else if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x36) && (gRxDataBuffer[2] == 0x72))
	{
		Repart_flag = 1;
		CurrBlock -= LastTransferBlockSize / MaxDataLengh;
		rem = LastTransferBlockSize % MaxDataLengh;
		if (CurrPos >= rem)
			CurrPos = CurrPos - rem;
		else
		{
			CurrBlock--;
			CurrPos = MaxDataLengh + CurrPos - rem;
		}
		DiagTransferData();
		if (First_data_Filename == 1)
		{
			First_data_Filename = 0;
		}
	}
	else if ((gRxDataBuffer[0] == 0x76) && (gRxDataBuffer[1] == (U8)(CurrentBlockIndex >> 24)) && (gRxDataBuffer[2] == (U8)(CurrentBlockIndex >> 16))
		&& (gRxDataBuffer[3] == (U8)(CurrentBlockIndex >> 8)) && (gRxDataBuffer[4] == (U8)CurrentBlockIndex))//CurrentBlockIndex not match
 //else if(gRxDataBuffer[0] == 0x76) //&& (gRxDataBuffer[1] == CurrentBlockIndex))    
	{
		if (First_data_Filename == 1)
		{
			First_data_Filename = 2;
		}
		if (CurrentBlockCnt >= DataBlockLength)
		{
			DiagStopTransferData();
		}
		else
		{
			Repart_flag = 0;
			CurrentBlockIndex++;
			DiagTransferData();
		}
	}
	else if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x36) && (gRxDataBuffer[2] == 0x25))
	{
		printf("TransferData timout!\n");
	}
}


/*****************************************************************************************
*  Name        : DiagEraseFlashSector_RequestRoutineResult
*  Description : send 31 service.
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagEraseFlashSector_RequestRoutineResult(void)
{
	Diag_Status = RequestEraseMemoryProcedureResult;
	gTxDataBuffer[0] = 0x31;
	gTxDataBuffer[1] = 0x03;
	gTxDataBuffer[2] = 0xff;
	gTxDataBuffer[3] = 0x00;

	txCount = 4;
	SendDataAtFhysicalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagEraseFlashSector_RequestRoutineResult
*  Description : deal response after send 31 service.
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagEraseFlashSector_RequestRoutineResultResps(void)
{
	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[1] == 0x31) && (gRxDataBuffer[2] == 0x78))
	{
		;
	}
	else if ((gRxDataBuffer[0] == 0x71) && (gRxDataBuffer[1] == 0x03) && (gRxDataBuffer[2] == 0xFF) && (gRxDataBuffer[3] == 0x00))
	{
		if (gRxDataBuffer[4] == 0x03)
		{
			DiagEraseFlashSector_RequestRoutineResult();
		}
		else if (gRxDataBuffer[4] == 0x02)
		{
			DiagEraseFlashSector_StopRoutine();
		}
	}
}


/*****************************************************************************************
*  Name        : DiagEnableNMAndCommunicationMessage
*  Description : send 28 service communcation control
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagEnableNMAndCommunicationMessage(void)
{
	Diag_Status = EnableNMAndCommunicationMessage;
	gTxDataBuffer[0] = 0x28;
	gTxDataBuffer[1] = 0x00;
	gTxDataBuffer[2] = 0x01;
	txCount = 3;
	SendDataAtFunctionalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagEnableNMAndCommunicationMessageResp
*  Description : deal response after send 28 service communcation control
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagEnableNMAndCommunicationMessageResp(void)
{
	if ((gRxDataBuffer[0] == 0x68) && (gRxDataBuffer[1] == 0x00))
	{
		DiagEnableDTCstorage();
	}
}
/*****************************************************************************************
*  Name        : DiagEnableDTCstorage
*  Description : send 85 service control DTC set
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagEnableDTCstorage(void)
{
	Diag_Status = EnableDTCstorage;
	gTxDataBuffer[0] = 0x85;
	gTxDataBuffer[1] = 0x01;
	txCount = 2;
	SendDataAtFunctionalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagEnableDTCstorageResp
*  Description : deal response after send 85 service control DTC set
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagEnableDTCstorageResp(void)
{
	if ((gRxDataBuffer[0] == 0xC5) && (gRxDataBuffer[1] == 0x01))
	{
		DiagClearAllDTC();
	}
}
/*****************************************************************************************
*  Name        : DiagEnableDTCstorage
*  Description : send 14 service clear all DTC
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagClearAllDTC(void)
{
	Diag_Status = ClearAllDTC;
	gTxDataBuffer[0] = 0x14;
	gTxDataBuffer[1] = 0xFF;
	gTxDataBuffer[2] = 0xFF;
	gTxDataBuffer[3] = 0xFF;
	txCount = 4;
	SendDataAtFunctionalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagEnableDTCstorage
*  Description : deal response after send 14 service clear all DTC
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagClearAllDTCResp(void)
{
	if ((gRxDataBuffer[0] == 0x7F) && (gRxDataBuffer[0] == 0x14) && (gRxDataBuffer[0] == 0x78))
	{

	}
	if (gRxDataBuffer[0] == 0x54)
	{
		DiagChangeToDefaultSession();
	}
}
/*****************************************************************************************
*  Name        : DiagChangeToDefaultSession
*  Description : send 10 01 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagChangeToDefaultSession(void)
{
	Diag_Status = ChangeToDefaultSession;
	gTxDataBuffer[0] = 0x10;
	gTxDataBuffer[1] = 0x01;
	txCount = 2;
	SendDataAtFunctionalConnector(gTxDataBuffer, txCount);
}
/*****************************************************************************************
*  Name        : DiagChangeToDefaultSession
*  Description : send 10 01 service
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void DiagChangeToDefaultSessionResp(void)
{
	if ((gRxDataBuffer[0] == 0x50) && (gRxDataBuffer[1] == 0x01))
	{
		if (curfileNumber < fileNumber - 1)
		{
			printf("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			if (rename(sourcefiles[curfileNumber], sourceFileMove[curfileNumber]) == 0)
			{
				printf("%sfile move correct \n", sourceFileMove[curfileNumber]);
			}
			else
			{
				printf("%sfile move error \n", sourceFileMove[curfileNumber]);
			}
			//logflashstatues(curfileNumber);

			curfileNumber++;
			DataCurrPos = 0;
			DataCurrIndex = 0;
			DataCurrAddr = 0;
			DataTotalLen = 0;
			DataBlockIndex = 0;

			crc = 0x00; /* initial value */
			tmp = 0x00;
			updateflag = 0;

			ReadFileData(curfileNumber);
			DiagStartExtendedSession();
			AS_AppCurFileNumber_Set(curfileNumber + 1);
		}
		else
		{
			if (rename(sourcefiles[curfileNumber], sourceFileMove[curfileNumber]) == 0)
			{
				printf("%sfile move correct \n", sourceFileMove[curfileNumber]);
			}
			else
			{
				printf("%sfile move error \n", sourceFileMove[curfileNumber]);
			}

		}
	}
}

/*****************************************************************************************
*  Name        : calcKey
*  Description : Calculate key to a given seed.
*  Parameter   : seed - Seed to which the key has to be calculated
*  Returns     : none
*****************************************************************************************/
void calcKey(unsigned char seed[])
{
	unsigned char bSeed[2];
	unsigned short remainder;
	int n;
	int i;
	bSeed[0] = seed[0]; /* MSB */
	bSeed[1] = seed[1]; /* LSB */
	remainder = 0xFFFE;
	for (n = 0; n < 2; n++)
	{
		/* Bring the next U8 into the remainder. */
		remainder ^= ((bSeed[n]) << 8);
		/* Perform modulo-2 division, a bit at a time. */
		for (i = 0; i < 8; i++)
		{
			/* Try to divide the current data bit. */
			if (remainder & 0x8000)
			{
				if (remainder & 0x0080)
				{
					remainder = (remainder << 1) ^ 0x8408;
				}
				else
				{
					remainder = (remainder << 1) ^ 0x8025;
				}
			}
			else
			{
				remainder = (remainder << 1);
			}
		}
	}
	/* The final remainder is the key */
	SecurityKey[0] = remainder >> 8; /* MSB */
	SecurityKey[1] = remainder; /* LSB */
}
/*****************************************************************************************
*  Name        : calcKey_MCU
*  Description : calculate security key to ecu
*  Parameter   : none
*  Returns     : none
*****************************************************************************************/
void calcKey_MCU(unsigned char seed[])
{
	U8 u8Xor[4] = { 0x65, 0x67, 0x77, 0xE9 };
	U8 u8Cal[4], u8i;

	/*The calculation is provied by Geely*/

	for (u8i = 0; u8i < 4; u8i++)
	{
		u8Cal[u8i] = seed[u8i] ^ u8Xor[u8i];
	}

	SecurityKey[0] = ((u8Cal[2] & 0x03) << 6) | ((u8Cal[3] & 0xFC) >> 2);
	SecurityKey[1] = ((u8Cal[3] & 0x03) << 6) | ((u8Cal[0] & 0x3F));
	SecurityKey[2] = (u8Cal[0] & 0xFC) | ((u8Cal[1] & 0xC0) >> 6);
	SecurityKey[3] = (u8Cal[1] & 0xFC) | (u8Cal[2] & 0x03);
}
/*****************************************************************************************
*  Name        : SendDataAtFunctionalConnector
*  Description : send data use Function Address message, deal CF mainly
*  Parameter   : double sendData[], unsigned short sendsize
*  Returns     : none
*****************************************************************************************/
void SendDataAtFunctionalConnector(double sendData[], unsigned short sendsize)
{
	unsigned short restSendSize;
	unsigned short currentSendSize;
	unsigned short loopCount;
	unsigned char CFnumber = 0;
	unsigned char CFsize = 0;
	int i = 0;

	Diag_Func_Request.Byte0 = 0;
	Diag_Func_Request.Byte1 = 0;
	Diag_Func_Request.Byte2 = 0;
	Diag_Func_Request.Byte3 = 0;
	Diag_Func_Request.Byte4 = 0;
	Diag_Func_Request.Byte5 = 0;
	Diag_Func_Request.Byte6 = 0;
	Diag_Func_Request.Byte7 = 0;

	if (sendsize < 8)
	{
		Diag_Func_Request.Byte0 = sendsize;

		switch (sendsize)
		{
		case 7:
			Diag_Func_Request.Byte7 = sendData[6];
		case 6:
			Diag_Func_Request.Byte6 = sendData[5];
		case 5:
			Diag_Func_Request.Byte5 = sendData[4];
		case 4:
			Diag_Func_Request.Byte4 = sendData[3];
		case 3:
			Diag_Func_Request.Byte3 = sendData[2];
		case 2:
			Diag_Func_Request.Byte2 = sendData[1];
		case 1:
			Diag_Func_Request.Byte1 = sendData[0];
			break;

		default:
			break;
		}

		TX_Diag_Func_Rx_HS_CAN_Transmit(&Diag_Func_Request);
	}
	else
	{
		Diag_Func_Request.Byte0 = 0x10;
		Diag_Func_Request.Byte1 = sendsize;

		Diag_Func_Request.Byte2 = sendData[0];
		Diag_Func_Request.Byte3 = sendData[1];
		Diag_Func_Request.Byte4 = sendData[2];
		Diag_Func_Request.Byte5 = sendData[3];
		Diag_Func_Request.Byte6 = sendData[4];
		Diag_Func_Request.Byte7 = sendData[5];

		TX_Diag_Func_Rx_HS_CAN_Transmit(&Diag_Func_Request);

		Sleep(cyclictimer);

		restSendSize = sendsize - 6;
		currentSendSize = 6;

		loopCount = (restSendSize / 7) + 1;
		CFnumber = 1;

		for (i = 0; i <= loopCount + 1; i++)
		{
			Diag_Func_Request.Byte0 = 0;
			Diag_Func_Request.Byte1 = 0;
			Diag_Func_Request.Byte2 = 0;
			Diag_Func_Request.Byte3 = 0;
			Diag_Func_Request.Byte4 = 0;
			Diag_Func_Request.Byte5 = 0;
			Diag_Func_Request.Byte6 = 0;
			Diag_Func_Request.Byte7 = 0;

			if ((restSendSize / 7) > 0)
			{
				CFsize = 7;
			}
			else
			{
				CFsize = restSendSize % 7;
			}

			Diag_Func_Request.Byte0 = 0x20 + CFnumber;

			switch (CFsize)
			{
			case 7:
				Diag_Func_Request.Byte7 = sendData[currentSendSize + 6];
			case 6:
				Diag_Func_Request.Byte6 = sendData[currentSendSize + 5];
			case 5:
				Diag_Func_Request.Byte5 = sendData[currentSendSize + 4];
			case 4:
				Diag_Func_Request.Byte4 = sendData[currentSendSize + 3];
			case 3:
				Diag_Func_Request.Byte3 = sendData[currentSendSize + 2];
			case 2:
				Diag_Func_Request.Byte2 = sendData[currentSendSize + 1];
			case 1:
				Diag_Func_Request.Byte1 = sendData[currentSendSize];

				TX_Diag_Func_Rx_HS_CAN_Transmit(&Diag_Func_Request);

				Sleep(cyclictimer);

				restSendSize = restSendSize - 7;
				currentSendSize = currentSendSize + 7;//currentSendSize is debug temp variable,could be ignore

				CFnumber++;

				if (CFnumber > 0xF)//max is 2F
				{
					CFnumber = 0;
				}

				break;

			default:
				break;
			}
		}
	}
}
/*****************************************************************************************
*  Name        : SendDataAtFhysicalConnector
*  Description : send data use Fhysical Address message, deal SF mainly
*  Parameter   : double sendData[], unsigned short sendsize
*  Returns     : none
*****************************************************************************************/
void SendDataAtFhysicalConnector(double sendData[], unsigned short sendsize)
{
	Diag_Phys_Request.Byte0 = 0;
	Diag_Phys_Request.Byte1 = 0;
	Diag_Phys_Request.Byte2 = 0;
	Diag_Phys_Request.Byte3 = 0;
	Diag_Phys_Request.Byte4 = 0;
	Diag_Phys_Request.Byte5 = 0;
	Diag_Phys_Request.Byte6 = 0;
	Diag_Phys_Request.Byte7 = 0;

	if (sendsize < 8)
	{
		Diag_Phys_Request.Byte0 = sendsize;

		switch (sendsize)
		{
		case 7:
			Diag_Phys_Request.Byte7 = sendData[6];
		case 6:
			Diag_Phys_Request.Byte6 = sendData[5];
		case 5:
			Diag_Phys_Request.Byte5 = sendData[4];
		case 4:
			Diag_Phys_Request.Byte4 = sendData[3];
		case 3:
			Diag_Phys_Request.Byte3 = sendData[2];
		case 2:
			Diag_Phys_Request.Byte2 = sendData[1];
		case 1:
			Diag_Phys_Request.Byte1 = sendData[0];
			break;
		default:
			break;
		}

		TX_AVM_Phys_Diag_Rx_Req_to_DVD_HS_CAN_Transmit(&Diag_Phys_Request);
	}
	else
	{
		Diag_Phys_Request.Byte0 = 0x10 | HIBYTE(sendsize);//length is 12bit represent
		Diag_Phys_Request.Byte1 = LOBYTE(sendsize);

		Diag_Phys_Request.Byte2 = sendData[0];
		Diag_Phys_Request.Byte3 = sendData[1];
		Diag_Phys_Request.Byte4 = sendData[2];
		Diag_Phys_Request.Byte5 = sendData[3];
		Diag_Phys_Request.Byte6 = sendData[4];
		Diag_Phys_Request.Byte7 = sendData[5];


		TX_AVM_Phys_Diag_Rx_Req_to_DVD_HS_CAN_Transmit(&Diag_Phys_Request);
	}
}
/*****************************************************************************************
*  Name        : SendFC
*  Description : send FC
*  Parameter   : double sendData[], unsigned short sendsize
*  Returns     : none
*****************************************************************************************/
void SendFC(void)
{
	Diag_Phys_Request.Byte0 = 0x30;
	Diag_Phys_Request.Byte1 = 0x0;
	Diag_Phys_Request.Byte2 = 0x0;

	TX_AVM_Phys_Diag_Rx_Req_to_DVD_HS_CAN_Transmit(&Diag_Phys_Request);
}
/*****************************************************************************************
*  Name        : SendDataAtFhysicalConnector_SecondPart
*  Description : send CF.
*  Parameter   : double sendData[], unsigned short sendsize
*  Returns     : none
*****************************************************************************************/
void SendDataAtFhysicalConnector_SecondPart(double sendData[], unsigned short sendsize)
{
	unsigned short restSendSize;
	unsigned short currentSendSize;
	unsigned short loopCount;
	unsigned char CFnumber = 0;
	unsigned char CFsize = 0;
	int i = 0;
	unsigned _int64 count = 0;

	restSendSize = sendsize - 6;
	currentSendSize = 6;

	loopCount = restSendSize / 7;

	CFnumber = 1;

	for (i = 0; i <= loopCount; i++)
	{
		Diag_Phys_Request.Byte0 = 0;
		Diag_Phys_Request.Byte1 = 0;
		Diag_Phys_Request.Byte2 = 0;
		Diag_Phys_Request.Byte3 = 0;
		Diag_Phys_Request.Byte4 = 0;
		Diag_Phys_Request.Byte5 = 0;
		Diag_Phys_Request.Byte6 = 0;
		Diag_Phys_Request.Byte7 = 0;

		if (restSendSize / 7 > 0)
		{
			CFsize = 7;
		}
		else
		{
			CFsize = restSendSize % 7;
		}

		Diag_Phys_Request.Byte0 = 0x20 + CFnumber;

		switch (CFsize)
		{
		case 7:
			Diag_Phys_Request.Byte7 = sendData[currentSendSize + 6];
		case 6:
			Diag_Phys_Request.Byte6 = sendData[currentSendSize + 5];
		case 5:
			Diag_Phys_Request.Byte5 = sendData[currentSendSize + 4];
		case 4:
			Diag_Phys_Request.Byte4 = sendData[currentSendSize + 3];
		case 3:
			Diag_Phys_Request.Byte3 = sendData[currentSendSize + 2];
		case 2:
			Diag_Phys_Request.Byte2 = sendData[currentSendSize + 1];
		case 1:
			Diag_Phys_Request.Byte1 = sendData[currentSendSize];
			TX_AVM_Phys_Diag_Rx_Req_to_DVD_HS_CAN_Transmit(&Diag_Phys_Request);

			//Sleep(1);

#if 0
			count = 0;
			while (count++ < 0x1000000)
			{
				;
			}
#endif
			restSendSize = restSendSize - 7;
			currentSendSize = currentSendSize + 7;

			CFnumber++;

			if (CFnumber > 0xF)
			{
				CFnumber = 0;
			}
			break;

		default:
			break;
		}
	}
}


/*****************************************************************************************
*  Name        : logflashstatues
*  Description : deal log file.
*  Parameter   : unsigned int n
*  Returns     : none
*****************************************************************************************/
void logflashstatues(unsigned int n)
{
	FILE *fp;
	char msg[250];

	if (n == 0)
	{
		strcpy(msg, "已刷新文件:\n");
		strcat(msg, sourceFile[n]);
		strcat(msg, "\n");
		fopen_s(&fp, logFile, "w");
		if (fp == NULL)
		{
			printf("Read log file error!\n");
		}
		else
		{
			//fwrite(msg,strlen(msg),1,fp);
			fclose(fp);
		}
	}
	else
	{
		strcpy(msg, sourceFile[n]);
		strcat(msg, "\n");
		fopen_s(&fp, logFile, "a+");
		if (fp == NULL)
		{
			printf("Read log file error!\n");
		}
		else
		{
			fwrite(msg, strlen(msg), 1, fp);
			fclose(fp);
		}
	}
}
