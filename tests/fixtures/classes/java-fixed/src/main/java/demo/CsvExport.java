package demo;

import java.util.List;
import java.util.stream.Collectors;

public class CsvExport {
    static String cell(String v) {
        return v.startsWith("=") || v.startsWith("+") || v.startsWith("-") || v.startsWith("@") ? "'" + v : v;
    }

    // text/csv download of every user
    String toCsv(List<List<String>> rows) {
        StringBuilder out = new StringBuilder();
        for (List<String> row : rows) {
            out.append(String.join(",", row.stream().map(CsvExport::cell).collect(Collectors.toList()))).append("\n");
        }
        return out.toString();
    }
}
