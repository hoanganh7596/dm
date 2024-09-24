/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.sqlinjection.introduction;

import static java.sql.ResultSet.CONCUR_UPDATABLE;
import static java.sql.ResultSet.TYPE_SCROLL_SENSITIVE;

import java.sql.*;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import org.owasp.webgoat.container.LessonDataSource;
import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AssignmentHints;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AssignmentHints(
    value = {
      "SqlStringInjectionHint.8.1",
      "SqlStringInjectionHint.8.2",
      "SqlStringInjectionHint.8.3",
      "SqlStringInjectionHint.8.4",
      "SqlStringInjectionHint.8.5"
    })
public class SqlInjectionLesson8 extends AssignmentEndpoint {

  private final LessonDataSource dataSource;

  public SqlInjectionLesson8(LessonDataSource dataSource) {
    this.dataSource = dataSource;
  }

  @PostMapping("/SqlInjection/attack8")
  @ResponseBody
  public AttackResult completed(@RequestParam String name, @RequestParam String auth_tan) {
    return injectableQueryConfidentiality(name, auth_tan);
  }

    protected AttackResult injectableQueryConfidentiality(String name, String auth_tan) {
        StringBuilder output = new StringBuilder();
        String query = "SELECT * FROM employees WHERE last_name = ? AND auth_tan = ?";

        try (Connection connection = dataSource.getConnection()) {
            try {
                // Loại bỏ TYPE_SCROLL_INSENSITIVE và CONCUR_UPDATABLE
                PreparedStatement preparedStatement = connection.prepareStatement(query);
                log(connection, query);

                // Gán giá trị cho các tham số truy vấn
                preparedStatement.setString(1, name);
                preparedStatement.setString(2, auth_tan);

                // Thực hiện truy vấn mà không truyền lại chuỗi SQL
                ResultSet results = preparedStatement.executeQuery();

                // Kiểm tra xem kết quả trả về có tồn tại không
                if (results != null) {
                    if (results.next()) {
                        // Tạo bảng kết quả từ ResultSet
                        output.append(generateTable(results));

                        // Nếu có nhiều hơn một bản ghi, báo cáo thành công
                        if (results.next()) { // Kiểm tra thêm bản ghi khác
                            return success(this)
                                    .feedback("sql-injection.8.success")
                                    .output(output.toString())
                                    .build();
                        } else {
                            // Chỉ có một bản ghi
                            return failed(this)
                                    .feedback("sql-injection.8.one")
                                    .output(output.toString())
                                    .build();
                        }

                    } else {
                        // Không có kết quả
                        return failed(this).feedback("sql-injection.8.no.results").build();
                    }
                } else {
                    return failed(this).build();
                }
            } catch (SQLException e) {
                return failed(this)
                        .output("<br><span class='feedback-negative'>" + e.getMessage() + "</span>")
                        .build();
            }

        } catch (Exception e) {
            return failed(this)
                    .output("<br><span class='feedback-negative'>" + e.getMessage() + "</span>")
                    .build();
        }
    }

    public static String generateTable(ResultSet results) throws SQLException {
        ResultSetMetaData resultsMetaData = results.getMetaData();
        int numColumns = resultsMetaData.getColumnCount();
        StringBuilder table = new StringBuilder();
        table.append("<table>");

        // Kiểm tra xem kết quả có tồn tại hay không
        if (!results.isBeforeFirst()) {
            table.append("Query Successful; however no data was returned from this query.");
        } else {
            // Tạo header cho bảng
            table.append("<tr>");
            for (int i = 1; i <= numColumns; i++) {
                table.append("<th>").append(escapeHtml(resultsMetaData.getColumnName(i))).append("</th>");
            }
            table.append("</tr>");

            // Duyệt qua từng hàng dữ liệu
            while (results.next()) {
                table.append("<tr>");
                for (int i = 1; i <= numColumns; i++) {
                    String columnValue = results.getString(i);
                    table.append("<td>").append(escapeHtml(columnValue != null ? columnValue : "")).append("</td>");
                }
                table.append("</tr>");
            }
        }

        table.append("</table>");
        return table.toString();
    }

    // Hàm để escape các ký tự đặc biệt trong HTML, chống tấn công XSS
    private static String escapeHtml(String input) {
        if (input == null) {
            return null;
        }
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;")
                .replace("/", "&#x2F;");
    }


    public static void log(Connection connection, String action) {
    action = action.replace('\'', '"');
    Calendar cal = Calendar.getInstance();
    SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    String time = sdf.format(cal.getTime());

    String logQuery =
        "INSERT INTO access_log (time, action) VALUES ('" + time + "', '" + action + "')";

    try {
      Statement statement = connection.createStatement(TYPE_SCROLL_SENSITIVE, CONCUR_UPDATABLE);
      statement.executeUpdate(logQuery);
    } catch (SQLException e) {
      System.err.println(e.getMessage());
    }
  }
}
