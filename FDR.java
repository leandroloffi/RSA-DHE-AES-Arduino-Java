package model;

public class FDR {

    private char operator;
    private int operand;

    public FDR(char operator, int operand) {
        this.operator = operator;
        this.operand = operand;
    }

    public char getOperator() {
        return operator;
    }

    public void setOperator(char operator) {
        this.operator = operator;
    }

    public int getOperand() {
        return operand;
    }

    public void setOperand(int operand) {
        this.operand = operand;
    }
}
