import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'dart:convert';

void main() => runApp(MyApp());

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: StatistikPage(),
    );
  }
}

class StatistikPage extends StatefulWidget {
  @override
  _StatistikPageState createState() => _StatistikPageState();
}

class _StatistikPageState extends State<StatistikPage> {
  List<dynamic> data = [];
  final int totalSlots = 60;

  @override
  void initState() {
    super.initState();
    fetchData();
  }

  Future<void> fetchData() async {
    final response = await http.get(Uri.parse('http://192.168.18.15:5000/api/statistik'));
    if (response.statusCode == 200) {
      setState(() {
        data = json.decode(response.body);
      });
    } else {
      throw Exception('Failed to load data');
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Statistik Parkir'),
      ),
      body: data.isEmpty
          ? Center(child: CircularProgressIndicator())
          : ListView.builder(
              itemCount: data.length,
              itemBuilder: (context, index) {
                int belumTerisi = data[index]['Belum terisi'];
                int occSlot = totalSlots - belumTerisi;
                return Card(
                  margin: EdgeInsets.all(10),
                  child: ListTile(
                    title: Text('Belum terisi: $belumTerisi'),
                    subtitle: Text('Waktu: ${data[index]['Waktu']}'),
                    trailing: Text('Terisi: $occSlot'), // Menampilkan sisa slot parkir
                  ),
                );
              },
            ),
    );
  }
}
