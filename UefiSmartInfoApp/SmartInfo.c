/** @file
  S.M.A.R.T. Info.

  Copyright (c) 2024, Yang Gang. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include <Uefi.h>
#include <IndustryStandard/Atapi.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>
#include <Protocol/AtaPassThru.h>



VOID DumpMem8(const VOID *Base, UINTN Size)
{
  const UINT8  *Data8;
        UINTN  Index;

  Data8 = (const UINT8*)Base;
  for(Index=0; Index<Size; Index++){
    Print(L"%02X ", Data8[Index]);
    if(((Index+1)%16)==0){
      Print(L"\n");
    }
  }
  Print(L"\n");

}



typedef struct {
  UINT8   Id;
  CHAR16  *Str;
} SMART_ATTRIBUTE_ID_STR;

STATIC SMART_ATTRIBUTE_ID_STR mSmartAttributeIdStr[] = {
  {0x01, L"Read Error Rate"},
  {0x02, L"Throughput Performance"},
  {0x03, L"Spin-Up Time"},
  {0x04, L"Start/Stop Count"},
  {0x05, L"Reallocated Sectors Count"},
  {0x06, L"Read Channel Margin"},
  {0x07, L"Seek Error Rate"},
  {0x08, L"Seek Time Performance"},
  {0x09, L"Power on Hours"},
  {0x0A, L"Spin Retry Count"},
  {0x0B, L"Calibration Retry Count"},
  {0x0C, L"Power Cycle Count"},
  {0x0D, L"Soft Read Error Rate"},
  {0x16, L"Current Helium Level"}, // Specific to He8 drives from HGST. 
  {0x17, L"Helium Condition Lower"}, // Specific to MG07+ drives from Toshiba.
  {0x18, L"Helium Condition Upper"},  // Specific to MG07+ drives from Toshiba.
  {0xA8, L"SATA PHY Error Count"},  // ? spec ?
  {0xAA, L"Bad Block Count"},
  {0xAB, L"SSD Program Fail Count"}, // (Kingston) The total number of flash program operation failures since the drive was deployed.[42] Identical to attribute 181.
  {0xAC, L"SSD Erase Fail Count"},  // (Kingston) Counts the number of flash erase failures. This attribute returns the total number of Flash erase operation failures since the drive was deployed. This attribute is identical to attribute 182.
  {0xAD, L"Erase Count"},  // SSD Wear Leveling Count -- Counts the maximum worst erase count on any block.
  {0xAE, L"Unexpected Power Loss Count"},  // Also known as "Power-off Retract Count"
  {0xAF, L"Power Loss Protection Failure"},
  {0xB0, L"Erase Fail Count"},
  {0xB1, L"Wear Range Delta"},
  {0xB2, L"Used Reserved Block Count"}, // "Pre-Fail" attribute used at least in Samsung devices.
  {0xB3, L"Used Reserved Block Count Total"}, // "Pre-Fail" attribute used at least in Samsung devices.
  {0xB4, L"Unused Reserved Block Count Total"}, // "Pre-Fail" attribute used at least in HP devices. If the value drops to 0 the device may become read-only to allow the user to retrieve stored data.
  {0xB5, L"Program Fail Count Total or Non-4K Aligned Access Count"},
  {0xB6, L"Erase Fail Count"},  // "Pre-Fail" Attribute used at least in Samsung devices.
  {0xB7, L"SATA Downshift Error Count or Runtime Bad Block"}, // Western Digital, Samsung or Seagate attribute.
  {0xB8, L"End-to-End error / IOEDC"},
  {0xB9, L"Head Stability"},
  {0xBA, L"Induced Op-Vibration Detection"},
  {0xBB, L"Reported Uncorrectable Errors"},
  {0xBC, L"Command Timeout"},
  {0xBD, L"High Fly Writes"},
  {0xBE, L"Temperature Difference or Airflow Temperature	Varies"},
  {0xBF, L"G-sense Error Rate"},
  {0xC0, L"Power-off Retract Count"},
  {0xC1, L"Load Cycle Count or Load"},
  {0xC2, L"Temperature or Temperature Celsius"},
  {0xC4, L"Reallocation Event Count"},
  {0xC5, L"Current Pending Sector Count"},
  {0xC6, L"(Offline) Uncorrectable Sector Count"},
  {0xC7, L"UltraDMA CRC Error Count	"},
  {0xC8, L"Multi-Zone Error Rate"},
  {0xC8, L"Write Error Rate (Fujitsu)"},
  {0xC9, L"Soft Read Error Rate or TA Counter Detected"},
  {0xCA, L"Data Address Mark errors or TA Counter Increased"},
  {0xCB, L"Run Out Cancel"},
  {0xCC, L"Soft ECC Correction"},
  {0xCD, L"Thermal Asperity Rate"},
  {0xCE, L"Flying Height"},
  {0xCF, L"Spin High Current"},
  {0xD0, L"Spin Buzz"},
  {0xD1, L"Offline Seek Performance"},
  {0xD2, L"Vibration During Write"},
  {0xD3, L"Vibration During Write"},
  {0xD4, L"Shock During Write"},
  {0xDC, L"Disk Shift"},
  {0xDD, L"G-Sense Error Rate"},
  {0xDE, L"Loaded Hours"},
  {0xDF, L"Load/Unload Retry Count"},
  {0xE0, L"Load Friction"},
  {0xE1, L"Load/Unload Cycle Count"},
  {0xE2, L"Load 'In'-time"},
  {0xE3, L"Torque Amplification Count"},
  {0xE4, L"Power-Off Retract Cycle"},
  {0xE6, L"GMR Head Amplitude (magnetic HDDs), Drive Life Protection Status (SSDs)"},
  {0xE7, L"Life Left (SSDs) or Temperature"},
  {0xE8, L"Endurance Remaining or Available Reserved Space"},
  {0xE9, L"Media Wearout Indicator (SSDs) or Power-On Hours"},
  {0xEA, L"Average erase count AND Maximum Erase Count"},
  {0xEB, L"Good Block Count AND System(Free) Block Count"},
  {0xF0, L"Head Flying Hours or 'Transfer Error Rate' (Fujitsu)"},
  {0xF1, L"Total LBAs Written or Total Host Writes"},
  {0xF2, L"Total LBAs Read or Total Host Reads"},
  {0xF3, L"Total LBAs Written Expanded or Total Host Writes Expanded"},
  {0xF4, L"Total LBAs Read Expanded or Total Host Reads Expanded"},
  {0xF5, L"Remaining Rated Write Endurance"},
  {0xF6, L"Cumulative host sectors written"},
  {0xF7, L"Host program page count"},
  {0xF8, L"Background program page count"},
  {0xF9, L"NAND Writes (1GiB)"},
  {0xFA, L"Read Error Retry Rate"},
  {0xFB, L"Minimum Spares Remaining"},
  {0xFC, L"Newly Added Bad Flash Block"},
  {0xFE, L"Free Fall Protection"},
  {0xC0, L"Unexpected Power Loss Count"},
  {0xC2, L"Temperature"},
  {0xDA, L"Number of CRC Error"},
  {0xE7, L"SSD Life Left"},
  {0xF1, L"Host Writes"},
};


#define NUMBER_ATA_SMART_ATTRIBUTES 30

#pragma pack(1)

typedef struct _EFI_SMART_ATTRIBUTE {
  UINT8     Id;
  UINT16    Flags;
  UINT8     Current;
  UINT8     Worst;
  UINT8     Raw[6];
  UINT8     Reserved;
} EFI_SMART_ATTRIBUTE;

typedef struct _EFI_SMART_READ_OUT_DATA {
  UINT16                  RevisionNumber;
  EFI_SMART_ATTRIBUTE     SmartAttribute[NUMBER_ATA_SMART_ATTRIBUTES];
  UINT8                   OffLineDataCollectionStatus;
  UINT8                   SelfTestExectionStatus;
  UINT16                  TotalTimeToCompleteOffLine;
  UINT8                   VendorSpecific_366;
  UINT8                   OffLineDataCollectionCapability;
  UINT16                  SmartCapability;
  UINT8                   ErrorLoggingCapability;
  UINT8                   VendorSpecific_371;
  UINT8                   ShortSelfTestRecommendPoolTime;
  UINT8                   ExtSelfTestRecommendPoolTime;
  UINT8                   ConveyanceSelfTestRecommendPoolTime;
  UINT16                  ExtSelfTestRecommendPoolTime2;
  UINT8                   Reserved_377_385[9];
  UINT8                   VendorSpecific_386_510[125];
  UINT8                   DataStructureChecksum;
} EFI_SMART_READ_OUT_DATA;

#pragma pack()



CHAR16 *
EFIAPI
GetSmartAttrIdStr (
  UINT8 Id
  )
{
  UINTN Index;
  for (Index = 0; Index < ARRAY_SIZE (mSmartAttributeIdStr); Index++) {
    if (Id == mSmartAttributeIdStr[Index].Id) {
      return mSmartAttributeIdStr[Index].Str;
    }
  }

  return L" ";
}



EFI_STATUS
EFIAPI
ShowSingleSmart (
  EFI_ATA_PASS_THRU_PROTOCOL      *AtaPassThru,
  UINT16                          Port,
  UINT16                          PortMp,
  EFI_HANDLE                      Handle
  )
{
  EFI_STATUS                        Status;
  EFI_ATA_COMMAND_BLOCK             Acb;
  EFI_ATA_PASS_THRU_COMMAND_PACKET  Packet;
  EFI_ATA_STATUS_BLOCK              *Asb;
  EFI_SMART_READ_OUT_DATA           SmartReadOut;

  EFI_SMART_READ_OUT_DATA           SmartReadThreshold;
  UINTN                             Index;

  if (AtaPassThru == NULL || Handle == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  Asb = (EFI_ATA_STATUS_BLOCK*)AllocateAlignedPages (
                                 EFI_SIZE_TO_PAGES (sizeof(EFI_ATA_STATUS_BLOCK)),
                                 AtaPassThru->Mode->IoAlign
                                 );
  if (Asb == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  // SMART_READ_DATA
  ZeroMem (Asb, sizeof (EFI_ATA_STATUS_BLOCK));
  ZeroMem (&Acb, sizeof (EFI_ATA_COMMAND_BLOCK));
  Acb.AtaCommand      = ATA_CMD_SMART;
  Acb.AtaFeatures     = ATA_SMART_READ_DATA;
  Acb.AtaCylinderLow  = ATA_CONSTANT_4F;
  Acb.AtaCylinderHigh = ATA_CONSTANT_C2;

  ZeroMem(&Packet, sizeof(Packet));
  Packet.Protocol         = EFI_ATA_PASS_THRU_PROTOCOL_PIO_DATA_IN;
  Packet.Length           = EFI_ATA_PASS_THRU_LENGTH_BYTES | EFI_ATA_PASS_THRU_LENGTH_SECTOR_COUNT;
  Packet.Asb              = Asb;
  Packet.Acb              = &Acb;
  Packet.InDataBuffer     = &SmartReadOut;
  Packet.InTransferLength = sizeof (EFI_SMART_READ_OUT_DATA);
  Packet.Timeout          = EFI_TIMER_PERIOD_SECONDS(3);

  Status = AtaPassThru->PassThru(
                          AtaPassThru,
                          Port,
                          PortMp,
                          &Packet,
                          NULL
                          );

  // SMART_READ_THRESHOLD
  ZeroMem (Asb, sizeof (EFI_ATA_STATUS_BLOCK));
  ZeroMem (&Acb, sizeof (EFI_ATA_COMMAND_BLOCK));
  Acb.AtaCommand      = ATA_CMD_SMART;
  Acb.AtaFeatures     = 0xD1;
  Acb.AtaCylinderLow  = ATA_CONSTANT_4F;
  Acb.AtaCylinderHigh = ATA_CONSTANT_C2;

  ZeroMem(&Packet, sizeof(Packet));
  Packet.Protocol         = EFI_ATA_PASS_THRU_PROTOCOL_PIO_DATA_IN;
  Packet.Length           = EFI_ATA_PASS_THRU_LENGTH_BYTES | EFI_ATA_PASS_THRU_LENGTH_SECTOR_COUNT;
  Packet.Asb              = Asb;
  Packet.Acb              = &Acb;
  Packet.InDataBuffer     = &SmartReadThreshold;
  Packet.InTransferLength = sizeof (EFI_SMART_READ_OUT_DATA);
  Packet.Timeout          = EFI_TIMER_PERIOD_SECONDS(3);

  Status = AtaPassThru->PassThru(
                          AtaPassThru,
                          Port,
                          PortMp,
                          &Packet,
                          NULL
                          );

  Print (L"SATA(%X,%X) %r\n", Port, PortMp, Status);

  Print (L"====================SMART_READ_DATA====================\n");
  DumpMem8 (&SmartReadOut, sizeof (EFI_SMART_READ_OUT_DATA));
  Print (L"DataStructureChecksum: 0x%x\n", SmartReadOut.DataStructureChecksum);
  Print (L"SmartCapability: 0x%x\n", SmartReadOut.SmartCapability);
  Print (L"ErrorLoggingCapability: %d\n", SmartReadOut.ErrorLoggingCapability);
  Print (L"OffLineDataCollectionStatus: 0x%x\n", SmartReadOut.OffLineDataCollectionStatus);
  Print (L"SelfTestExectionStatus: 0x%x\n", SmartReadOut.SelfTestExectionStatus);

  Print (L"====================SMART_READ_THRESHOLD====================\n");
  DumpMem8 (&SmartReadThreshold, sizeof (EFI_SMART_READ_OUT_DATA));

  Print (L"====================S.M.A.R.T====================\n");
  Print (L"ID Cur Wor Thr RawValues(6) Attribute Name\n");
  for (Index = 0; Index < NUMBER_ATA_SMART_ATTRIBUTES; Index++) {
    if (SmartReadOut.SmartAttribute[Index].Id == 0) {
      continue;
    }
    Print (L"%02x %03d %03d %03d %02x%02x%02x%02x%02x%02x ", 
             SmartReadOut.SmartAttribute[Index].Id,
             SmartReadOut.SmartAttribute[Index].Current,
             SmartReadOut.SmartAttribute[Index].Worst,
             (UINT8)(SmartReadOut.SmartAttribute[Index].Id == SmartReadThreshold.SmartAttribute[Index].Id) ? SmartReadThreshold.SmartAttribute[Index].Flags : 0,
             SmartReadOut.SmartAttribute[Index].Raw[5],
             SmartReadOut.SmartAttribute[Index].Raw[4],
             SmartReadOut.SmartAttribute[Index].Raw[3],
             SmartReadOut.SmartAttribute[Index].Raw[2],
             SmartReadOut.SmartAttribute[Index].Raw[1],
             SmartReadOut.SmartAttribute[Index].Raw[0]);
    Print (L"%s\n", GetSmartAttrIdStr(SmartReadOut.SmartAttribute[Index].Id));
  }

  FreeAlignedPages(Asb, EFI_SIZE_TO_PAGES(sizeof(EFI_ATA_STATUS_BLOCK)));
  return Status;
}


EFI_STATUS
EFIAPI
ShowHddSmartStatus (
  VOID
  )
{
  EFI_STATUS                      Status;
  UINTN                           HandleCount;
  EFI_HANDLE                      *HandleBuffer = NULL;
  UINTN                           Index;
  UINT16                          SataPort;
  UINT16                          SataPortMp; 
  EFI_ATA_PASS_THRU_PROTOCOL      *AtaPassThru;

  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiAtaPassThruProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  DEBUG ((DEBUG_INFO, "AtaPassThru Count: %d\n", HandleCount));

  for (Index = 0; Index < HandleCount; Index++) {

    Status = gBS->HandleProtocol (
                    HandleBuffer[Index],
                    &gEfiAtaPassThruProtocolGuid,
                    &AtaPassThru
                    );

    SataPort = 0xFFFF;
    while (TRUE) {
      Status = AtaPassThru->GetNextPort(AtaPassThru, &SataPort);
      if (EFI_ERROR (Status)) {
        break;
      }
      SataPortMp = 0xFFFF;
      while (TRUE) {
        Status = AtaPassThru->GetNextDevice(AtaPassThru, SataPort, &SataPortMp);
        if (EFI_ERROR (Status)) {
          break;
        }

        ShowSingleSmart(AtaPassThru, SataPort, SataPortMp, HandleBuffer[Index]);
      }
    }
  }

  if (HandleBuffer != NULL){
    FreePool(HandleBuffer);
  }
  return EFI_SUCCESS;
}

/**
  The user Entry Point for Application. The user code starts with this function
  as the real entry point for the application.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{

  ShowHddSmartStatus();

  return EFI_SUCCESS;
}
