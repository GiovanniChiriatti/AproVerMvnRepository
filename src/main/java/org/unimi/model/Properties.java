package org.unimi.model;

import javafx.scene.Node;

public class Properties {
	private String[][] stringSpecification = new String[10][10];
	private Node[][] nodeSpecification = new Node[10][10];
	private Node[][] nodeResult = new Node[10][10];
	private int row, rowFound;
	private int column, colFound;
	public Properties () {
		row=0;
		rowFound=0;
		column=0;
		colFound=0;
		for (int i=0; i<10; i++) {
			for (int j=0; j<10; j++) {
				nodeSpecification[i][j]=null;
				nodeResult[i][j]=null;
				stringSpecification[i][j]="";
			}			
		}
	}
	public void setProperties(String propertieIn, Node nodeIn, int rowIn, int colIn ) {
		System.out.println(" setProperties - propertieIn;" + propertieIn + " rowIn:" + rowIn + " colIn:"+colIn );
		stringSpecification[rowIn][colIn]=propertieIn;
		nodeSpecification[rowIn][colIn]=nodeIn;
	}

	public Node findProperties(String propertieIn) {
		System.out.println("findProperties - propertieIn:"+propertieIn);
		String[] partProporties = splitProperties(propertieIn);
		System.out.println("---------- splitProperties -----------");
		for (String e : partProporties) {
			System.out.println("Elemento " + e);
		}
		
		for (int i = 0; i < 10; i++) {
			for (int j = 0; j < 10; j++) {
				if (stringSpecification[i][j] != null && !stringSpecification[i][j].isEmpty()) {
					if (verifyProp(stringSpecification[i][j], partProporties)) {
						stringSpecification[i][j] ="";
						rowFound=i;
						colFound=j;
						System.out.println("findProperties - trovato:"+nodeSpecification[i][j] + " i " + i + " j "+ j);
						return nodeSpecification[i][j];
					}
				}
			}
		}
		
		System.out.println("findProperties - NON trovato return null");
		return null;
	}
	private String[] splitProperties(String propertieIn) {
		String lineSpecification2=propertieIn;
		String lineSpecification=propertieIn;
		
		for(int i = 0; i < lineSpecification2.length()-1; i++) {
		  int j = i +1;
		  char lettera = lineSpecification2.charAt(i);
		  char letteraSuccessiva = lineSpecification2.charAt(j);
		  if (lettera == '!' && letteraSuccessiva != '(' ) {
			  lineSpecification=lineSpecification.replace(String.valueOf(lettera)+String.valueOf(letteraSuccessiva), String.valueOf(lettera)+"("+String.valueOf(letteraSuccessiva));
		  }
		  //fai quello che vuoi con la lettera

		}
		
		lineSpecification=lineSpecification.replace("!(af ", "!af(");
		lineSpecification=lineSpecification.replace("!(ag ", "!ag(");
		lineSpecification=lineSpecification.replace("!(ax ", "!ax(");
		lineSpecification=lineSpecification.replace("!(ef ", "!ef(");
		lineSpecification=lineSpecification.replace("!(eg ", "!eg(");
		lineSpecification=lineSpecification.replace("!(ex ", "!ex(");
		lineSpecification=lineSpecification.replace("!(AF ", "!AF(");
		lineSpecification=lineSpecification.replace("!(AG ", "!AG(");
		lineSpecification=lineSpecification.replace("!(AX ", "!AX(");
		lineSpecification=lineSpecification.replace("!(EF ", "!EF(");
		lineSpecification=lineSpecification.replace("!(EG ", "!EG(");
		lineSpecification=lineSpecification.replace("!(EX ", "!EX(");
		lineSpecification=lineSpecification.replace(" AF (", " AF(");
		lineSpecification=lineSpecification.replace(" AG (", " AG(");
		lineSpecification=lineSpecification.replace(" AX (", " AX(");
		lineSpecification=lineSpecification.replace(" EF (", " EF(");
		lineSpecification=lineSpecification.replace(" EG (", " EG(");
		lineSpecification=lineSpecification.replace(" EX (", " EX(");
		lineSpecification=lineSpecification.replace(" AF ", " AF(");
		lineSpecification=lineSpecification.replace(" AG ", " AG(");
		lineSpecification=lineSpecification.replace(" AX ", " AX(");
		lineSpecification=lineSpecification.replace(" EF ", " EF(");
		lineSpecification=lineSpecification.replace(" EG ", " EG(");
		lineSpecification=lineSpecification.replace(" EX ", " EX(");
		lineSpecification=lineSpecification.replace(" & ", " and ");
		lineSpecification=lineSpecification.replace(" | ", " or ");
		
		
		String[] partSpecification = new String[15];
		int riga=-1;
		lineSpecification2=lineSpecification.substring(17,lineSpecification.indexOf("  is "));
		for (int i = 0; i < lineSpecification2.length(); i++) {
			if (i < lineSpecification2.length() - 2) {
				String treLettere = String.valueOf(lineSpecification2.charAt(i))
						+ String.valueOf(lineSpecification2.charAt(i + 1))
						+ String.valueOf(lineSpecification2.charAt(i + 2));
			//	System.out.println("treLettere:" + treLettere);
				if (treLettere.equals("and")){
					riga++;
					partSpecification[riga] = " and ";
			//		System.out.println("*->" +partSpecification[riga] + "<--*");
				}
				if (treLettere.equals(" or")){
					riga++;
					partSpecification[riga] = " or ";
			//		System.out.println("*->" +partSpecification[riga] + "<--*");
				}
				if (treLettere.equals("!AF") || treLettere.equals("!AG") || treLettere.equals("!AX")
						|| treLettere.equals("!EF") || treLettere.equals("!EG") || treLettere.equals("!EX")
						|| treLettere.equals("AF(") || treLettere.equals("AG(") || treLettere.equals("AX(")
						|| treLettere.equals("EF(") || treLettere.equals("EG(") || treLettere.equals("EX(")) {
					boolean primo = true;
					riga++;
					int aperta = 1;
					int chiusa = 0;
					
					for (int j = i; j < lineSpecification2.length(); j++) {
				//		System.out.println("lineSpecification2.charAt(j):" + lineSpecification2.charAt(j));
						if (lineSpecification2.charAt(j) == '(') {
							if (primo) {
								primo = false;
							} else {
								aperta++;
							}
						}
						if (lineSpecification2.charAt(j) == ')') {
							chiusa++;
						}

						if (aperta == chiusa || j == lineSpecification2.length() - 1) {
							partSpecification[riga] = lineSpecification2.substring(i, j+1);
				//			System.out.println("*->" +partSpecification[riga] + "<--*");
							i = j;
							break;
						}
						if (lineSpecification2.charAt(j) == ' ') {
							partSpecification[riga] = lineSpecification2.substring(i, j);
				//			System.out.println("*->" +partSpecification[riga] + "<--*");
							i = j;
							break;
						}
					}

				}
			}
		}
		return partSpecification;
	}
	private boolean verifyProp(String eleTable, String[] partProporties) {
		String eletabIn= eleTable.toUpperCase();
		for (int i=0; i<10; i++) {
			if (partProporties[i] !=null && !partProporties[i].isEmpty()) {
				if (!eletabIn.contains(partProporties[i].toUpperCase())) {
					return false;
				}
			}
		}
		
		return true;
	}
	public void setNodeResult(Node nodeResultIn,int rowIn, int colIn ) {
		System.out.println(" setNodeResult - nodeResultIn;" + nodeResultIn + " rowIn:" + rowIn + " colIn:"+colIn );

		nodeResult[rowIn][colIn]=nodeResultIn;
	}
	public Node getNodeResult(int rowIn, int colIn ) {
		return nodeResult[rowIn][colIn];
	}
	public int getRowFound() {
		return rowFound;
	}
	public int getColFound() {
		return colFound;
	}
}
