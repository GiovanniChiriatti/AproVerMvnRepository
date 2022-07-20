package org.unimi.model;

public class ConfigurationDataProprieties {
	private String[][] proprietiesValue  = new String[16][16];
	private String[] listNameTab = new String[16];

	private int row, column;

	public ConfigurationDataProprieties() {
		row=-1;
		column=-1;
		for (int i = 0 ; i< 10; i++) {
			listNameTab[i]="";
			for (int j = 0 ; j< 10; j++) {
				proprietiesValue[i][j]="";
			}			
		}
	}

	public void setListNameTab(String stringListNameTab, String stringListPropTab) {
		if (stringListNameTab.isEmpty()) {
			return;
		}
		for (int i=0; i<10;i++ ){
			if (this.listNameTab[i]==null || this.listNameTab[i].isEmpty()) {
				row=i;
				break;
			}
		}
		if (row < 10) {
			column=-1;
			this.listNameTab[row] = stringListNameTab;
			this.proprietiesValue[row][0] = stringListPropTab;
		}
	}
	public void updListNameTab(int rowAppo,String stringListNameTab, String stringListPropTab) {
		if (rowAppo < 16) {
			this.listNameTab[rowAppo] = stringListNameTab;
			this.proprietiesValue[rowAppo][0] = stringListPropTab;
		}
	}
	public void delListTab(int rowAppo) {
		if (rowAppo < 10) {
			for (int i = rowAppo+1; i <= 10 ; i++) {
				this.listNameTab[i-1]=this.listNameTab[i];
				for (int j = 0; j < 10 ; j++) {
					this.proprietiesValue[i-1][j]=this.proprietiesValue[i][j];
				}
			}
			this.listNameTab[9] =null;
			for (int j = 0; j < 10 ; j++) {
				this.proprietiesValue[9][j]=null;
			}
		}
	}
	public void delPropertiesTab(int rowAppo,int colAppo) {

		if (rowAppo < 10 && colAppo < 10) {
				for (int j = colAppo+1; j < 10 ; j++) {
					this.proprietiesValue[rowAppo][j-1]=this.proprietiesValue[rowAppo][j];
				}
			this.proprietiesValue[row][9]=null;
		}
	}

	public String getListNameTab(int rowAppo) {
		if (rowAppo < 10) {
			return this.listNameTab[rowAppo];
		}
		return null;
	}

	public void setProprietiesValue(String stringproprietiesValue) {
		if (column < 10) {
			column++;
			this.proprietiesValue[row][column] = stringproprietiesValue;
		}
	}
	public int setNextPropertisValue(String stringproprietiesValue, int rowAppo) {
		if (rowAppo < 10) {
			for (int columnAppo = 0; columnAppo < 10; columnAppo++) {
				if (this.proprietiesValue[rowAppo][columnAppo].isEmpty()) {
					this.proprietiesValue[rowAppo][columnAppo] = stringproprietiesValue;
					return columnAppo;
				}
				
			}
		}
		return 99;
	}
	public void setElePropertisValue(String stringproprietiesValue, int rowAppo, int columnAppo) {
		if (rowAppo < 10 && columnAppo < 10) {
			this.proprietiesValue[rowAppo][columnAppo] = stringproprietiesValue;
		}
		return ;
	}

	public String getProprietiesValue(int rowAppo, int columnAppo) {
		if (columnAppo < 10 && rowAppo < 10) {
			return this.proprietiesValue[rowAppo][columnAppo];
		}
		return null;
	}
	public int getNumListNameTab() {
		row=0;
		for (int i=0; i<10;i++ ){
			if (this.listNameTab[i]==null || this.listNameTab[i].isEmpty()) {
				break;
			}
			row=i;
		}
		return row;
	}

}
