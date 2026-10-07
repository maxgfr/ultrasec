package demo;

import java.util.List;

public class CsvExport {
    // text/csv download of every user
    String toCsv(List<List<String>> rows) {
        StringBuilder out = new StringBuilder();
        for (List<String> row : rows) {
            out.append(String.join(",", row)).append("\n");
        }
        return out.toString();
    }
}
