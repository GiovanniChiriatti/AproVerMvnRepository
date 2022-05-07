package org.unimi.model;

public class ConfigurationDataProprieties {
	private String[][] proprietiesValue  = new String[16][16];
	private String[] listNameTab = new String[16];
	private int row, column;

	public ConfigurationDataProprieties() {
		row=-1;
		column=-1;
		// TODO Auto-generated constructor stub
	}

	public void setListNameTab(String stringListNameTab) {
		if (row < 16) {
			row++;
			column=-1;
			this.listNameTab[row] = stringListNameTab;
		}
	}
	public String getListNameTab(int rowAppo) {
		if (rowAppo < 16) {
			return this.listNameTab[rowAppo];
		}
		return null;
	}
	public void setProprietiesValue(String stringproprietiesValue) {
		if (column < 16) {
			column++;
			this.proprietiesValue[row][column] = stringproprietiesValue;
		}
	}
	public String getProprietiesValue(int rowAppo, int columnAppo) {
		if (columnAppo < 16 && rowAppo < 16) {
			return this.proprietiesValue[rowAppo][columnAppo];
		}
		return null;
	}

}
