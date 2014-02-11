#include<windows.h>
#include<stdio.h>

BYTE *arr;
int main()
{
	int w=640,i;
	int h=480;
	srand(time(NULL));
  BITMAPFILEHEADER bfh;
  BITMAPINFOHEADER bih;
  bfh.bfType=0x4d42;
  bfh.bfSize=sizeof(BITMAPFILEHEADER);
  bfh.bfReserved1=0;
  bfh.bfReserved2=0;
  bfh.bfOffBits=sizeof(BITMAPFILEHEADER)+sizeof(BITMAPINFOHEADER);
  
  arr=malloc(w*h*3);
  printf("%d\n%0.8x\n",w*h*3,arr);
  for(i=0;i<w*h*3;i=i+3)
  {
	    arr[i]=rand()%255;
		arr[i+1]=rand()%255;
		arr[i+2]=rand()%255;
  }
  bih.biSize=sizeof(BITMAPINFOHEADER);
  bih.biWidth=w;
  bih.biHeight=h;
  bih.biPlanes=0x01;
  bih.biBitCount=24;
  bih.biCompression=BI_RGB;
  
  FILE *fptr;
  fptr=fopen("new.bmp","wb+");
  printf("%d\n",fwrite((void*)&bfh,sizeof(bfh),1,fptr));
  printf("%d\n",fwrite((void*)&bih,sizeof(bih),1,fptr));
  printf("%d\n",fwrite(arr,w*h*3,1,fptr));
  fclose(fptr);
}
